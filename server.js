// Import your new tools
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt'); // For hashing passwords
const jwt = require('jsonwebtoken'); // For user login tokens
const { Pool } = require('pg');  // For connecting to PostgreSQL
const url = require('url'); // NEW: For parsing the DATABASE_URL

const app = express();
// Render automatically provides the PORT environment variable
const port = process.env.PORT || 3000;

// --- CONFIGURATION ---
// This is the "secret key" for creating and verifying login tokens
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-nobody-knows';

// Middleware
app.use(cors()); // Allows your frontend to talk to this backend
app.use(express.json()); // Allows the server to understand JSON data

// --- STEP 1: DATABASE CONNECTION (UPDATED FOR RENDER) ---
// Render provides the DATABASE_URL environment variable
const dbUrl = process.env.DATABASE_URL;

if (!dbUrl) {
    console.error("FATAL ERROR: DATABASE_URL environment variable not set.");
    process.exit(1);
}

// Parse the URL provided by Render
const params = url.parse(dbUrl);
const auth = params.auth ? params.auth.split(':') : [];

const config = {
    user: auth[0],
    password: auth[1],
    host: params.hostname,
    port: params.port,
    database: params.pathname ? params.pathname.split('/')[1] : '',
    ssl: { 
        // CRITICAL FIX: Forces SSL for connection between Render services
        rejectUnauthorized: false 
    }
};

const pool = new Pool(config);

// Check connection
pool.connect((err, client, done) => {
    if (err) {
        // This will now successfully log the full error stack if it fails
        console.error('Error connecting to PostgreSQL database:', err.stack);
        return;
    }
    console.log('Connected to PostgreSQL database!');
    done();
});

// --- STEP 2: API ROUTES ---

// Test route
app.get('/', (req, res) => {
    res.json({ message: "Welcome to the Arcade Hub API! The server is running!" });
});

/**
 * API Route: POST /api/signup
 * Creates a new user.
 */
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const query = 'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING user_id';
        const values = [username, passwordHash];
        const result = await pool.query(query, values);

        console.log('User created with ID:', result.rows[0].user_id);
        res.status(201).json({
            success: true,
            message: 'User created successfully!',
            userId: result.rows[0].user_id
        });

    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ success: false, message: 'Username already exists.' });
        }
        console.error('Error during signup:', error.stack);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

/**
 * API Route: POST /api/login
 * Logs in an existing user and returns a token.
 */
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    try {
        // --- Find the user ---
        const query = 'SELECT * FROM users WHERE username = $1';
        const result = await pool.query(query, [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ success: false, message: 'Invalid username or password.' });
        }

        // --- Check the password ---
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }

        // --- Create Login Token (JWT) ---
        const token = jwt.sign(
            { userId: user.user_id, username: user.username },
            JWT_SECRET,
            { expiresIn: '1d' } // Token lasts for 1 day
        );

        // --- Send Success Response ---
        res.json({
            success: true,
            message: 'Login successful!',
            token: token,
            username: user.username
        });

    } catch (error) {
        console.error('Error during login:', error.stack);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});


/**
 * API Route: GET /api/scores/:game
 * Gets the top 10 high scores for a specific game.
 * This is a PUBLIC route - no login required.
 */
app.get('/api/scores/:game', async (req, res) => {
    const { game } = req.params; // :game comes from the URL (e.g., "snake")

    try {
        // This query joins the 'scores' and 'users' tables to get the username
        const query = `
            SELECT u.username, s.score, s.saved_at
            FROM scores s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.game_name = $1
            ORDER BY s.score DESC
            LIMIT 10;
        `;
        
        const result = await pool.query(query, [game]);
        
        res.json({
            success: true,
            scores: result.rows // Send back the list of scores
        });

    } catch (error) {
        console.error('Error fetching scores:', error.stack);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});


// --- STEP 3: SECURITY MIDDLEWARE ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid token.' });
        }
        
        req.user = user;
        next();
    });
}


// --- STEP 4: PROTECTED ROUTES ---

/**
 * API Route: POST /api/save-score
 * Saves a new score for the *currently logged-in user*.
 * This route is PROTECTED by our authenticateToken middleware.
 */
app.post('/api/save-score', authenticateToken, async (req, res) => {
    // We can access req.user because authenticateToken added it
    const { userId } = req.user;
    const { gameName, score } = req.body;

    if (!gameName || score === undefined) {
        return res.status(400).json({ success: false, message: 'Game name and score are required.' });
    }

    try {
        const query = 'INSERT INTO scores (user_id, game_name, score) VALUES ($1, $2, $3) RETURNING score_id';
        const values = [userId, gameName, score];
        
        const result = await pool.query(query, values);
        
        res.status(201).json({
            success: true,
            message: 'Score saved!',
            scoreId: result.rows[0].score_id
        });

    } catch (error) {
        console.error('Error saving score:', error.stack);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});


// --- STEP 5: START THE SERVER ---
app.listen(port, () => {
    console.log(`Backend server is running on http://localhost:${port}`);
});
