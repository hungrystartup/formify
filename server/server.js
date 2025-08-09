const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
app.use(cookieParser());
require('dotenv').config();
const port = process.env.PORT;
app.use(express.json());
// CORS configuration
const cors = require('cors');

const allowedOrigins = process.env.FRONTEND_URL,

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // must be true for cookies
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Very important: handle OPTIONS preflight
app.options('*', cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));

app.use(express.urlencoded({ extended: true }));
const mysql = require('mysql2/promise');
const pool = mysql.createPool({
    user: process.env.DATABASE_USER,
    database: process.env.DATABASE_NAME,
    host: process.env.DATABASE_HOST,
    password: process.env.DATABASE_PASSWORD,
    waitForConnections: true,
    connectionLimit: 30,
    queueLimit: 0
});
const sanitizeHtml = require('sanitize-html');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { redisClient, connectRedis } = require('./redis.js');
const rateLimiter = require('./ratelimiter.js');

// connect once globally on server start
connectRedis();

function verifyToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
}
app.get("/ping", (req, res) => {
    res.status(200).send({success: true});
});
app.post("/signup", rateLimiter, async (req, res) => {
    const { name, email, password } = req.body;

    try {
        if (!name || !email || !password) {
            return res.status(400).send({ success: false, error: "Fields cannot be empty" });
        }

        const [rows] = await pool.execute("SELECT id FROM users WHERE email = ?", [email]);
        if (rows.length > 0) {
            return res.status(409).send({ success: false, error: "Email has already been used" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const apiKey = require('crypto').randomBytes(32).toString('hex');

        const [result] = await pool.execute(
            "INSERT INTO users(username, email, password, api_key) VALUES(?, ?, ?, ?)",
            [name, email, hashedPassword, apiKey]
        );

        const userId = result.insertId;

        const token = jwt.sign(
            { id: userId, email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, {
            httpOnly: true, // Prevent JavaScript access
            secure: true, // Required for HTTPS and SameSite=None
            sameSite: 'None', // Allow cross-subdomain requests
            domain: '.bluhorizon.work',
            maxAge: 24 * 60 * 60 * 1000 // 1 day in milliseconds
        });

        res.status(200).send({ success: true, message: "Sign up successful" });
    } catch (err) {
        console.error(err.message);
        res.status(400).send({ success: false, error: err.message });
    }
});

app.post("/login", rateLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).send({ success: false, error: "Fields cannot be empty" });
        }

        const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [email]);
        const user = rows[0];

        const isMatch = user && await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(409).send({ success: false, error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, {
            httpOnly: true, // Prevent JavaScript access
            secure: true, // Required for HTTPS and SameSite=None
            sameSite: 'None', // Allow cross-subdomain requests
            domain: '.bluhorizon.work',
            maxAge: 24 * 60 * 60 * 1000 // 1 day in milliseconds
        });
        console.log('Set-Cookie: token=', token);
        res.status(200).send({ success: true });
    } catch (err) {
        console.error(err.message);
        res.status(400).send({ success: false, error: err.message });
    }
});

app.get("/authorize", verifyToken, (req, res) => {
    res.send({ success: true });
});
//getting api key
app.get('/apikey', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute("SELECT api_key from users WHERE id = ? ", [req.user.id]);

        if (rows.length === 0) return res.status(400).send({ success: false, error: "user not found" });

        res.status(200).send({ success: true, message: rows[0].api_key });
    } catch (err) {
        console.log(err.message);
        res.status(400).send({ success: false, error: err.message });
    }
});
//  New endpoint to fetch message limit

app.get("/api/total", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT total_messages FROM users WHERE id = ?",
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ total: rows[0].total_messages });

    } catch (err) {
        console.error("total fetch error:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/api/current", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT current_message FROM users WHERE id = ?",
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ current: rows[0].current_message });

    } catch (err) {
        console.error("current fetch error:", err);
        res.status(500).json({ error: "Server error" });
    }
});
app.get("/api/limit", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT max_message FROM users WHERE id = ?",
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ limit: rows[0].max_message });

    } catch (err) {
        console.error("Limit fetch error:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/v1/submit/:apikey", rateLimiter, async (req, res) => {
    const referrer = req.get('referer');
    const safeReferrer = (referrer || "").substring(0, 255);
    const { apikey } = req.params;
    const { email, message, _redirect } = req.body;

    if (!email || !message) {
        return res.status(400).json({ success: false, error: "Message content or email is required" });
    }

    // Sanitize input
    const cleanEmail = sanitizeHtml(email.trim(), {
        allowedTags: [],
        allowedAttributes: {}
    });

    const cleanMessage = sanitizeHtml(message.trim(), {
        allowedTags: [],
        allowedAttributes: {}
    });

    // Basic email format validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        return res.status(400).json({ success: false, error: "Invalid email format" });
    }

    try {
        const [[user]] = await pool.execute(
            "SELECT id, email, max_message, current_message, status FROM users WHERE api_key = ?",
            [apikey]
        );

        if (!user) return res.status(404).json({ error: "User not found" });

        if (user.current_message >= user.max_message) {
           return res.redirect(`${process.env.FRONTEND_URL}/limitreached.html`);
        }

        await pool.execute(
            "INSERT INTO messages (user_id, content, submitted_email, site_url) VALUES (?, ?, ?, ?)",
            [user.id, cleanMessage, cleanEmail, safeReferrer]
        );

        await pool.execute(
            "UPDATE users SET current_message = current_message + 1, total_messages = total_messages + 1 WHERE id = ?",
            [user.id]
        );

        // Redirect logic
        if (user.status === 0) {
             return res.redirect(`${process.env.FRONTEND_URL}/thanks.html`);
        }

        if (user.status === 1 && _redirect) {
            return res.redirect(_redirect);
        }

        return res.status(200).json({ success: true, message: "Message received" });

    } catch (err) {
    console.error("MySQL Submit error:", err); // full error object
    res.status(500).json({ 
        error: "Server error", 
        details: err.sqlMessage || err.message 
    });
}
});

app.get("/api/messages", verifyToken, async (req, res) => {
    const limit = 5;

    try {
        const sql = `
            SELECT id, submitted_email, content, received_at, site_url
            FROM messages
            WHERE user_id = ?
            ORDER BY received_at DESC
            LIMIT ${limit}
        `;

        const [messages] = await pool.query(sql, [req.user.id]);

        res.status(200).json({ success: true, messages });
    } catch (err) {
        console.error("Fetch messages error:", err);
        res.status(500).json({ error: "Server error" });
    }
});


app.get("/api/message", verifyToken, async (req, res) => {
    const limit = parseInt(req.query.limit) || 4;
    const offset = parseInt(req.query.offset) || 0;

    try {
        const sql = `
            SELECT id, content, received_at, site_url
            FROM messages
            WHERE user_id = ?
            ORDER BY received_at DESC
            LIMIT ${limit} OFFSET ${offset}
        `;

        const [messages] = await pool.query(sql, [req.user.id]);

        res.status(200).send({ success: true, messages });
    } catch (err) {
        console.log(err.message);
        res.status(400).send({ success: false, error: err.message });
    }
});

app.get("/api/status", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute("SELECT status FROM users WHERE id = ? ", [req.user.id]);

        if (rows.length === 0) return res.status(400).send({ success: false, error: "User not found" });

        res.status(200).send({ success: true, stats: rows[0].status });
    } catch (err) {
        console.log(err.message);
        res.status(400).send({ success: false, error: err.message });
    }
});

//getting the username
app.get("/username", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute("SELECT username FROM users WHERE id = ? ", [req.user.id]);
        if (rows.length === 0) return res.status(400).send({ success: false, error: "user not found" });

        res.status(200).send({ success: true, message: rows[0].username });
    } catch (err) {
        console.log(err.message);
        res.status(200).send({ success: false, error: err.message });
    }
});

app.post("/logout", rateLimiter, (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true, // Prevent JavaScript access
            secure: true, // Required for HTTPS and SameSite=None
            domain: '.bluhorizon.work',
            sameSite: 'None', // Allow cross-subdomain requests
        });
        res.status(200).send({ success: true });
    } catch (err) {
        console.log(err.message);
        res.status(400).send({ success: false, error: err.message });
    }
});

app.get('/message-progress', verifyToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await pool.execute(
            "SELECT current_message, max_message FROM users WHERE id = ?",
            [userId]
        );

        if (rows.length === 0) return res.status(404).json({ success: false, error: "User not found" });

        const { current_message, max_message } = rows[0];
        res.status(200).json({ success: true, current_message, max_message });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});
app.get("/api/message-stats", verifyToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await pool.query(
            `
           SELECT 
            SUM(CASE WHEN DATE(received_at) = CURDATE() THEN 1 ELSE 0 END) AS today,
            SUM(CASE WHEN YEARWEEK(received_at, 1) = YEARWEEK(CURDATE(), 1) THEN 1 ELSE 0 END) AS this_week,
            SUM(CASE WHEN MONTH(received_at) = MONTH(CURDATE()) AND YEAR(received_at) = YEAR(CURDATE()) THEN 1 ELSE 0 END) AS this_month,
            SUM(CASE WHEN YEAR(received_at) = YEAR(CURDATE()) THEN 1 ELSE 0 END) AS this_year
            FROM messages
            WHERE user_id = ?
            `,
            [userId]
        );

        res.json({ success: true, ...rows[0] });
    } catch (err) {
        console.error("Stats fetch error:", err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

app.get('/delete', verifyToken, async(req, res) => {
    const id = req.query.id;
    try{

        const [[ user ]] = await pool.execute("SELECT status FROM users WHERE id = ? ", [req.user.id]);
        if(user.length == 0) return res.status(400).send({success: false, error: "User does not exist"});

        if (user.status == 0) return res.status(401).send({success: false, error: "Only premium users can delete messages"});
        
        await pool.execute("DELETE FROM messages WHERE id = ?", [id]);
        await pool.execute( "UPDATE users SET current_message = current_message - 1, total_messages = total_messages - 1 WHERE id = ?",
            [req.user.id])
        res.status(200).send({success: true, message: "Message successfully deleted"});
    }catch(err){
        console.log(err.message);
    }
});
app.listen(port, () => console.log(`Connection started on port: ${port}`));
