const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.error("Error connecting to SQLite database:", err.message);
  } else {
    console.log("Connected to SQLite database.");
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

module.exports = db;