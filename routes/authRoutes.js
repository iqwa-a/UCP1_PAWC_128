const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../database/db');
const router = express.Router();

// Route Signup
router.post('/signup', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    // Hash password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('Hashing error:', err);
            return res.status(500).send('Error hashing password');
        }

        console.log('Password hash:', hash); // Debug log
        db.query(
            'INSERT INTO users (username, password) VALUES (?, ?)', 
            [username.trim(), hash], 
            (err, result) => {
                if (err) {
                    console.error('Database error during registration:', err);
                    return res.status(500).send('Error registering user');
                }
                console.log('User registered:', result.insertId); // Debug log
                res.redirect('/login'); // Redirect to login page
            }
        );
    });
});

// Route untuk menampilkan form signup
router.get('/signup', (req, res) => {
    res.render('signup', {
        layout: 'layouts/main-layouts'
    });
});

// Route Login
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    // Query untuk mencari user berdasarkan username
    db.query('SELECT * FROM users WHERE username = ?', [username.trim()], (err, results) => {
        if (err) {
            console.error('Database error during login:', err);
            return res.status(500).send('Error fetching user');
        }
        if (results.length === 0) {
            return res.status(400).send('User not found');
        }

        const user = results[0];
        console.log('User fetched from database:', user); // Debug log

        // Bandingkan password yang dimasukkan dengan hash yang ada di database
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Password comparison error:', err);
                return res.status(500).send('Error checking password');
            }
            if (!isMatch) {
                console.warn('Incorrect password for user:', username); // Debug log
                return res.status(401).send('Incorrect password');
            }

            // Jika password cocok, simpan userId di sesi
            req.session.userId = user.id;
            console.log('Login successful for user:', username); // Debug log
            res.redirect('/'); // Redirect ke halaman utama
        });
    });
});

// Route untuk menampilkan form login
router.get('/login', (req, res) => {
    res.render('login', {
        layout: 'layouts/main-layouts'
    });
});

// Route Logout
router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login'); // Redirect ke halaman login
    });
});

module.exports = router;
