const db = require("../config/db");

class Request {
  static create(request, callback) {
    const { userId, type, area, location, bedrooms, style, budget, payment, description } = request;
    const query = `
      INSERT INTO requests (userId, type, area, location, bedrooms, style, budget, payment, description)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.run(query, [userId, type, area, location, bedrooms, style, budget, payment, description], callback);
  }

  static findByUserId(userId, callback) {
    const query = `SELECT * FROM requests WHERE userId = ?`;
    db.all(query, [userId], callback);
  }
}

module.exports = Request;