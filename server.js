require("dotenv").config();
const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const Database = require("better-sqlite3");

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ---------- DB ----------
const db = new Database("eventhub.db");
db.exec(`
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  location TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  capacity INTEGER NOT NULL DEFAULT 50,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(event_id, user_id)
);
`);

// ---------- Mail (SMTP) ----------
function makeTransport() {
  // If SMTP not set, we’ll still run the app and just skip sending.
  if (!process.env.SMTP_HOST) return null;

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || "true") === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendRegistrationEmail({ to, eventTitle, startsAt, location, link }) {
  const transporter = makeTransport();
  if (!transporter) return;

  const from = process.env.MAIL_FROM || "EventHub <no-reply@example.com>";
  const text =
`You're registered ✅

Event: ${eventTitle}
When: ${startsAt}
Where: ${location}

View event: ${link}
`;

  await transporter.sendMail({
    from,
    to,
    subject: `Registration confirmed: ${eventTitle}`,
    text,
  });
}

// ---------- Middleware ----------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  const events = db.prepare(`
    SELECT e.*, u.name AS host_name,
      (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS reg_count
    FROM events e
    JOIN users u ON u.id = e.host_user_id
    ORDER BY datetime(e.starts_at) ASC
  `).all();

  res.render("index", { events });
});

app.get("/signup", (req, res) => res.render("signup", { error: null }));
app.post("/signup", async (req, res) => {
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!name || !email || !password) return res.render("signup", { error: "Fill all fields." });

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return res.render("signup", { error: "Email already registered." });

  const password_hash = await bcrypt.hash(password, 12);
  const info = db.prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)")
    .run(name, email, password_hash);

  req.session.user = { id: info.lastInsertRowid, name, email };
  res.redirect("/");
});

app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return res.render("login", { error: "Invalid email or password." });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.render("login", { error: "Invalid email or password." });

  req.session.user = { id: user.id, name: user.name, email: user.email };
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/events/new", requireAuth, (req, res) => {
  res.render("new-event", { error: null });
});

app.post("/events/new", requireAuth, (req, res) => {
  const title = (req.body.title || "").trim();
  const description = (req.body.description || "").trim();
  const location = (req.body.location || "").trim();
  const starts_at = req.body.starts_at;
  const capacity = Number(req.body.capacity || 50);

  if (!title || !description || !location || !starts_at) {
    return res.render("new-event", { error: "Fill all required fields." });
  }
  if (!Number.isFinite(capacity) || capacity < 1 || capacity > 5000) {
    return res.render("new-event", { error: "Capacity must be 1–5000." });
  }

  const info = db.prepare(`
    INSERT INTO events (host_user_id, title, description, location, starts_at, capacity)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(req.session.user.id, title, description, location, starts_at, capacity);

  res.redirect(`/events/${info.lastInsertRowid}`);
});

app.get("/events/:id", (req, res) => {
  const id = Number(req.params.id);

  const event = db.prepare(`
    SELECT e.*, u.name AS host_name,
      (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS reg_count
    FROM events e
    JOIN users u ON u.id = e.host_user_id
    WHERE e.id = ?
  `).get(id);

  if (!event) return res.status(404).send("Event not found");

  let alreadyRegistered = false;
  if (req.session.user) {
    const r = db.prepare("SELECT id FROM registrations WHERE event_id = ? AND user_id = ?")
      .get(id, req.session.user.id);
    alreadyRegistered = !!r;
  }

  res.render("event", { event, alreadyRegistered, error: null, ok: null });
});

app.post("/events/:id/register", requireAuth, async (req, res) => {
  const id = Number(req.params.id);

  const event = db.prepare(`
    SELECT e.*, u.name AS host_name,
      (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS reg_count
    FROM events e
    JOIN users u ON u.id = e.host_user_id
    WHERE e.id = ?
  `).get(id);

  if (!event) return res.status(404).send("Event not found");

  if (event.reg_count >= event.capacity) {
    return res.render("event", { event, alreadyRegistered: false, error: "Event is full.", ok: null });
  }

  try {
    db.prepare("INSERT INTO registrations (event_id, user_id) VALUES (?, ?)")
      .run(id, req.session.user.id);
  } catch {
    return res.render("event", { event, alreadyRegistered: true, error: null, ok: "You’re already registered ✅" });
  }

  try {
    await sendRegistrationEmail({
      to: req.session.user.email,
      eventTitle: event.title,
      startsAt: event.starts_at,
      location: event.location,
      link: `${BASE_URL}/events/${id}`,
    });
  } catch (e) {
    console.warn("Email failed:", e.message);
  }

  const refreshed = db.prepare(`
    SELECT e.*, u.name AS host_name,
      (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS reg_count
    FROM events e
    JOIN users u ON u.id = e.host_user_id
    WHERE e.id = ?
  `).get(id);

  res.render("event", { event: refreshed, alreadyRegistered: true, error: null, ok: "Registered ✅ (email sent if SMTP is set)" });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`EventHub running on ${BASE_URL}`);
});
