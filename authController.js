const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const register = (req, res) => {
  const { fullName, email, username, password, city, region, expertise, workRegion, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  User.create({ fullName, email, username, password: hashedPassword, city, region, expertise, workRegion, role }, (err) => {
    if (err) {
      return res.status(500).json({ message: "Error registering user." });
    }
    res.status(201).json({ message: "User registered successfully." });
  });
};

const login = (req, res) => {
  const { email, password } = req.body;

  User.findByEmail(email, (err, user) => {
    if (err || !user) {
      return res.status(404).json({ message: "User not found." });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({ message: "Invalid password." });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, "secret-key", { expiresIn: "1h" });
    res.status(200).json({ token });
  });
};

module.exports = { register, login };