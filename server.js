// Importing required modules
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// Initialize app
const app = express();
app.use(bodyParser.json());
// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/allnik', { useNewUrlParser: true, useUnifiedTopology: true });
// User schema
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    city: { type: String, required: true },
    region: { type: String, required: true },
    userType: { type: String, required: true },
    expertise: { type: String },
    workRegion: { type: String },
});
const User = mongoose.model('User', userSchema);
// Generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user._id, username: user.username, userType: user.userType }, 'secretKey', { expiresIn: '1h' });
};
// Register endpoint
app.post('/api/register', async (req, res) => {
    const { fullName, email, username, password, city, region, userType, expertise, workRegion } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
const user = new User({ fullName, email, username, password: hashedPassword, city, region, userType, expertise, workRegion });
try {
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
} catch (error) {
    res.status(400).json({ error: error.message });
}

});
// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = generateToken(user);
        res.status(200).json({ token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});
// Middleware to protect routes
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (token) {
        jwt.verify(token, 'secretKey', (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(403);
    }
};
// Protected route example
app.get('/api/user', authenticateJWT, (req, res) => {
    res.json({ message: 'User data', user: req.user });
});
// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(Server is running on port ${PORT});
});
