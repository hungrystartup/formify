// server/server.js
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const sanitizeHtml = require("sanitize-html");

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 3000;

// DB Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Auth Middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// Rate Limiter
const submitLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { success: false, error: "Too many requests, slow down." },
});

// Register
app.post("/register", async (req, res) => {
  const { email, password, max_message } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const [rows] = await pool.execute("INSERT INTO users (email, password, max_message) VALUES (?, ?, ?)", [email, hashed, max_message || 100]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

  try {
    const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ error: "Login error" });
  }
});

// Submit Form
app.post("/submit/:apikey", submitLimiter, async (req, res) => {
  const { apikey } = req.params;
  const { name, email, message } = req.body;

  if (!name || !email || !message) return res.status(400).json({ error: "Missing fields" });

  const sanitized = {
    name: sanitizeHtml(name),
    email: sanitizeHtml(email),
    message: sanitizeHtml(message),
  };

  try {
    const [rows] = await pool.execute("SELECT id FROM users WHERE api_key = ?", [apikey]);
    if (!rows.length) return res.status(404).json({ error: "Invalid API Key" });

    await pool.execute("INSERT INTO messages (user_id, name, email, message) VALUES (?, ?, ?, ?)", [rows[0].id, sanitized.name, sanitized.email, sanitized.message]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Limit Info
app.get("/api/limit", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT max_message FROM users WHERE id = ?", [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ limit: rows[0].max_message });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Ping
app.get("/", (req, res) => {
  res.send("Formify backend running");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
