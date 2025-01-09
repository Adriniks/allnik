const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to SQLite database
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.error("Error connecting to SQLite database:", err.message);
  } else {
    console.log("Connected to SQLite database.");

    // Create users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullName TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        city TEXT,
        region TEXT,
        expertise TEXT,
        workRegion TEXT,
        role TEXT NOT NULL DEFAULT 'user'
      )
    `);

    // Create requests table
    db.run(`
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        type TEXT NOT NULL,
        area INTEGER NOT NULL,
        location TEXT NOT NULL,
        bedrooms INTEGER,
        style TEXT,
        budget INTEGER,
        payment TEXT,
        description TEXT,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);

    // Create properties table
    db.run(`
      CREATE TABLE IF NOT EXISTS properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        type TEXT NOT NULL,
        area INTEGER NOT NULL,
        location TEXT NOT NULL,
        price INTEGER NOT NULL,
        paymentConditions TEXT,
        customerType TEXT,
        description TEXT,
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);
  }
});

// Register a new user
app.post("/api/auth/register", (req, res) => {
  const { fullName, email, username, password, city, region, expertise, workRegion, role } = req.body;

  // Hash the password
  const hashedPassword = bcrypt.hashSync(password, 8);

  // Insert user into the database
  const query = `
    INSERT INTO users (fullName, email, username, password, city, region, expertise, workRegion, role)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.run(query, [fullName, email, username, hashedPassword, city, region, expertise, workRegion, role], (err) => {
    if (err) {
      return res.status(500).json({ message: "Error registering user." });
    }
    res.status(201).json({ message: "User registered successfully." });
  });
});

// Login user
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const query = `SELECT * FROM users WHERE email = ?`;
  db.get(query, [email], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check password
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({ message: "Invalid password." });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, role: user.role }, "secret-key", { expiresIn: "1h" });
    res.status(200).json({ token });
  });
});

// Middleware to authenticate JWT token
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ message: "No token provided." });
  }

  jwt.verify(token, "secret-key", (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Failed to authenticate token." });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

// Get user profile (protected route)
app.get("/api/user/profile", authMiddleware, (req, res) => {
  const query = `SELECT * FROM users WHERE id = ?`;
  db.get(query, [req.userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ message: "User not found." });
    }
    res.status(200).json(user);
  });
});

// Create a new property request (protected route)
app.post("/api/requests", authMiddleware, (req, res) => {
  const { type, area, location, bedrooms, style, budget, payment, description } = req.body;

  const query = `
    INSERT INTO requests (userId, type, area, location, bedrooms, style, budget, payment, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.run(query, [req.userId, type, area, location, bedrooms, style, budget, payment, description], (err) => {
    if (err) {
      return res.status(500).json({ message: "Error creating request." });
    }
    res.status(201).json({ message: "Request created successfully." });
  });
});

// Get all requests for a user (protected route)
app.get("/api/requests", authMiddleware, (req, res) => {
  const query = `SELECT * FROM requests WHERE userId = ?`;
  db.all(query, [req.userId], (err, requests) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching requests." });
    }
    res.status(200).json(requests);
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});