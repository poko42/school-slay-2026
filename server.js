import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import cookieParser from "cookie-parser";

const app = express();
const PORT = process.env.PORT || 3000;

// ====== НАСТРОЙКИ ВЛАДЕЛЬЦА (поменяй!) ======
const ADMIN_USER = process.env.ADMIN_USER || "owner";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-me-strong-pass";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-session-secret";
// ============================================

const DATA_FILE = path.join(process.cwd(), "votes.json");

app.use(express.json({ limit: "256kb" }));
app.use(cookieParser());
app.use(express.static(process.cwd())); // раздаёт index.html и admin.html

function loadVotes() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveVotes(items) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(items, null, 2), "utf8");
}

function newSessionToken() {
  return crypto.randomBytes(24).toString("hex");
}

function hashToken(token) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(token).digest("hex");
}

const sessions = new Set(); // hash(token)

function requireAdmin(req, res, next) {
  const token = req.cookies?.admin_session;
  if (!token) return res.status(401).json({ error: "unauthorized" });
  const hashed = hashToken(token);
  if (!sessions.has(hashed)) return res.status(401).json({ error: "unauthorized" });
  next();
}

// Приём голосов
app.post("/api/vote", (req, res) => {
  const votes = req.body?.votes;
  if (!Array.isArray(votes) || votes.length === 0) {
    return res.status(400).send("Bad payload");
  }
  for (const v of votes) {
    if (!v || typeof v.category !== "string" || typeof v.choice !== "string") {
      return res.status(400).send("Bad vote item");
    }
  }

  const all = loadVotes();
  all.push({
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    votes
  });
  saveVotes(all);

  res.json({ ok: true });
});

// Логин владельца
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: "wrong_credentials" });
  }

  const token = newSessionToken();
  sessions.add(hashToken(token));
  res.cookie("admin_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false
  });

  res.json({ ok: true });
});

// Выход
app.post("/api/admin/logout", (req, res) => {
  const token = req.cookies?.admin_session;
  if (token) sessions.delete(hashToken(token));
  res.clearCookie("admin_session");
  res.json({ ok: true });
});

// Результаты (только владелец)
app.get("/api/admin/results", requireAdmin, (req, res) => {
  const all = loadVotes();
  const agg = {};

  for (const entry of all) {
    for (const v of entry.votes) {
      agg[v.category] ??= {};
      agg[v.category][v.choice] = (agg[v.category][v.choice] || 0) + 1;
    }
  }

  res.json({ total_ballots: all.length, results: agg });
});

// Админка (страница)
app.get("/admin", (req, res) => {
  res.sendFile(path.join(process.cwd(), "admin.html"));
});

app.listen(PORT, () => {
  console.log("Server running on http://localhost:" + PORT);
});
