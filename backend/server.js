require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const authRoutes = require("./routes/authroutes");

const app = express();

app.use(cors());
app.use(express.json());
app.use("/api/auth", authRoutes);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

// Test backend
app.get("/", (req, res) => {
    res.send("Argus Backend is Running");
});

// Test PostgreSQL
app.get("/api/test-db", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");

        res.json({
            message: "PostgreSQL connected successfully!",
            time: result.rows[0].now
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "PostgreSQL connection failed"
        });
    }
});

const PORT = 5000;

app.listen(PORT, () => {
    console.log(`Argus server running on http://localhost:${PORT}`);
});