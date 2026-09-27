import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import session from 'express-session';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(cors({
    origin: true,
    credentials: true // Required for sessions with CORS
}));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'makunu-secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Set to true if using HTTPS
        maxAge: 3600000 // 1 hour
    }
}));


const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'makunutyper',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// GET /api/leaderboard?mode=time&config=30
app.get('/api/leaderboard', async (req, res) => {
    const { mode, config } = req.query;
    try {
        const [rows] = await pool.query(
            'SELECT * FROM leaderboard WHERE mode = ? AND config = ? ORDER BY wpm DESC LIMIT 10',
            [mode, config]
        );
        res.json(rows);
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Initialize a per-session signing token
app.get('/api/session-init', (req, res) => {
    if (!req.session.sigKey) {
        req.session.sigKey = crypto.randomBytes(32).toString('hex');
    }
    res.json({ token: req.session.sigKey });
});

// POST /api/session-score (signed)
app.post('/api/session-score', (req, res) => {
    const { wpm, raw_wpm, accuracy, mode, config } = req.body || {};

    // Require per-session signing key
    const sigKey = req.session.sigKey;
    if (!sigKey) {
        return res.status(401).json({ error: 'session not initialized' });
    }

    const sigHeader = req.header('x-makunu-signature');
    const tsHeader = req.header('x-makunu-timestamp');

    if (!sigHeader || !tsHeader) {
        return res.status(401).json({ error: 'missing signature' });
    }

    const timestamp = Number(tsHeader);
    if (!Number.isFinite(timestamp)) {
        return res.status(400).json({ error: 'invalid timestamp' });
    }

    const now = Date.now();
    const windowMs = parseInt(process.env.SIGNATURE_WINDOW_MS || '300000', 10); // 5 minutes default
    if (Math.abs(now - timestamp) > windowMs) {
        return res.status(401).json({ error: 'signature expired' });
    }

    // Build canonical string for signing
    const canonical = [wpm, raw_wpm, accuracy, mode, config, timestamp].map(v => String(v)).join('|');
    const expected = crypto.createHmac('sha256', Buffer.from(sigKey, 'hex')).update(canonical).digest('hex');

    // Constant-time compare
    const valid = expected.length === sigHeader.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sigHeader));
    if (!valid) {
        return res.status(401).json({ error: 'invalid signature' });
    }

    // Validate WPM
    if (wpm > 500) {
        return res.status(400).json({ error: 'invalid data' });
    }

    req.session.lastScore = { wpm, raw_wpm, accuracy, mode, config };
    res.json({ success: true });
});

// POST /api/leaderboard
app.post('/api/leaderboard', async (req, res) => {
    const { name, recaptchaToken } = req.body;
    const lastScore = req.session.lastScore;

    if (!lastScore) {
        return res.status(400).json({ error: 'No test attempt found in session' });
    }

    const { wpm, raw_wpm, accuracy, mode, config } = lastScore;

    // Reject if WPM exceeds limit
    if (wpm > 500) {
        return res.status(400).json({ error: 'invalid data' });
    }

    // Verify Recaptcha
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    // Only verify if secret key is present (allows development without captcha if not configured)
    if (secretKey) {
        if (!recaptchaToken) {
            return res.status(400).json({ error: 'Recaptcha token is missing' });
        }

        try {
            const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;
            const response = await axios.post(verificationUrl);

            if (!response.data.success) {
                return res.status(400).json({ error: 'Recaptcha verification failed' });
            }
        } catch (error) {
            console.error('Recaptcha verification error:', error);
            return res.status(500).json({ error: 'Recaptcha verification error' });
        }
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO leaderboard (name, wpm, raw_wpm, accuracy, mode, config) VALUES (?, ?, ?, ?, ?, ?)',
            [name, wpm, raw_wpm, accuracy, mode, config]
        );

        // Clear session score after saving
        delete req.session.lastScore;

        res.status(201).json({ id: result.insertId });
    } catch (error) {
        console.error('Error saving score:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Serve static files from the 'dist' directory
app.use(express.static(path.join(__dirname, '../dist')));

// Catch-all route to serve the frontend's index.html
app.get('*all', (req, res) => {
    res.sendFile(path.join(__dirname, '../dist/index.html'));
});

const PORT = process.env.SERVER_PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
