const db = require("../config/db");

class User {
  static create(user, callback) {
    const { fullName, email, username, password, city, region, expertise, workRegion, role } = user;
    const query = `
      INSERT INTO users (fullName, email, username, password, city, region, expertise, workRegion, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.run(query, [fullName, email, username, password, city, region, expertise, workRegion, role], callback);
  }

  static findByEmail(email, callback) {
    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], callback);
  }

  static findById(id, callback) {
    const query = `SELECT * FROM users WHERE id = ?`;
    db.get(query, [id], callback);
  }
}

module.exports = User;