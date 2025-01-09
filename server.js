// server.js

// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB Connected'))
  .catch((err) => console.error(err));

// User Schema
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  city: { type: String, required: true },
  region: { type: String, required: true },
  userType: { type: String, enum: ['user', 'advisor', 'admin'], default: 'user' },
  expertise: { type: String }, // Only for advisors
  workRegion: { type: String }, // Only for advisors
});

// Hash password before saving
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// User Model
const User = mongoose.model('User', UserSchema);

// Request Schema
const RequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  advisorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  requestType: { type: String, enum: ['rent', 'buy', 'pre-buy', 'partnership'], required: true },
  area: { type: Number, required: true },
  location: { type: String, required: true },
  bedrooms: { type: Number, required: true },
  style: { type: String },
  budget: { type: Number, required: true },
  paymentConditions: { type: String },
  description: { type: String },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

// Request Model
const Request = mongoose.model('Request', RequestSchema);

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Register User
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, username, password, city, region, userType, expertise, workRegion } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    user = new User({
      fullName,
      email,
      username,
      password,
      city,
      region,
      userType,
      expertise,
      workRegion,
    });

    await user.save();

    const payload = { userId: user.id, userType: user.userType };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const payload = { userId: user.id, userType: user.userType };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Create Request
app.post('/api/requests', authMiddleware, async (req, res) => {
  const { requestType, area, location, bedrooms, style, budget, paymentConditions, description } = req.body;

  try {
    const newRequest = new Request({
      userId: req.user.userId,
      requestType,
      area,
      location,
      bedrooms,
      style,
      budget,
      paymentConditions,
      description,
    });

    await newRequest.save();

    res.status(201).json(newRequest);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get Requests for Advisor
app.get('/api/requests/advisor', authMiddleware, async (req, res) => {
  try {
    const advisor = await User.findById(req.user.userId);
    if (!advisor || advisor.userType !== 'advisor') {
      return res.status(403).json({ msg: 'Access denied' });
    }

    const requests = await Request.find({ location: advisor.workRegion, status: 'pending' });
    res.json(requests);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Update Request Status
app.put('/api/requests/:id', authMiddleware, async (req, res) => {
  const { status } = req.body;

  try {
    const request = await Request.findById(req.params.id);
    if (!request) return res.status(404).json({ msg: 'Request not found' });

    request.status = status;
    await request.save();

    res.json(request);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get User Profile
app.get('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));