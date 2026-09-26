const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db");

const router = express.Router();

router.post("/register", async (req, res) => {
    try {
        const { name, username, email, password } = req.body;

        // Check if all fields are provided
        if (!name || !username || !email || !password)  {
            return res.status(400).json({
                message: "Name, email and password are required"
            });
        }

        // Check if email already exists
        const existingUser = await pool.query(
            "SELECT id FROM users WHERE email = $1",
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                message: "Email or username already registered"
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user in PostgreSQL
        const result = await pool.query(
            `INSERT INTO users (name, username, email, password)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, username, email, created_at`,
            [name, username, email, hashedPassword]
        );

        res.status(201).json({
            message: "User registered successfully",
            user: result.rows[0]
        });

    } catch (error) {
        console.error("Registration error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


// LOGIN
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if email and password are provided
        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        // Find user by email
        const result = await pool.query(
            "SELECT id, name, username, email, password FROM users WHERE email = $1",
            [email]
        );

        // User not found
        if (result.rows.length === 0) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const user = result.rows[0];

        // Compare entered password with hashed password
        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Login successful
        res.status(200).json({
            message: "Login successful",
            user: {
                id: user.id,
                name: user.name,
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

module.exports = router;