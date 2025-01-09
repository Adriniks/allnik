const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// اتصال به MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error(err));

// اسکیما و مدل‌ها
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  city: { type: String, required: true },
  region: { type: String, required: true },
  userType: { type: String, enum: ['user', 'advisor', 'admin'], default: 'user' },
  expertise: { type: String },
  workRegion: { type: String },
});

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', UserSchema);

// روت‌های API
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

// سرویس فایل‌های استاتیک (فرانت‌اند)
app.use(express.static(path.join(__dirname)));

// روت اصلی برای فرانت‌اند
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// شروع سرور
const PORT = process.env.PORT || 10000; // استفاده از پورت پیش‌فرض Render
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));