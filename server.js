const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// اتصال به دیتابیس
mongoose.connect("mongodb://localhost:27017/allnik", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// مدل‌های دیتابیس
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" }, // "user", "advisor", "admin"
});
const RequestSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  description: String,
  status: { type: String, default: "active" }, // "active", "accepted", "completed"
  advisorId: mongoose.Schema.Types.ObjectId,
});
const User = mongoose.model("User", UserSchema);
const Request = mongoose.model("Request", RequestSchema);

// توابع کمکی
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Unauthorized");
  jwt.verify(token, "secret_key", (err, user) => {
    if (err) return res.status(403).send("Forbidden");
    req.user = user;
    next();
  });
};

// ثبت‌نام کاربر
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    res.status(201).send("User registered successfully");
  } catch (error) {
    res.status(400).send("Error: " + error.message);
  }
});

// ورود کاربر
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send("User not found");
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).send("Invalid credentials");

  const token = jwt.sign({ userId: user._id, role: user.role }, "secret_key");
  res.status(200).json({ token });
});

// ثبت درخواست
app.post("/create-request", authenticate, async (req, res) => {
  const { description } = req.body;
  try {
    const request = new Request({ userId: req.user.userId, description });
    await request.save();
    res.status(201).send("Request created successfully");
  } catch (error) {
    res.status(400).send("Error: " + error.message);
  }
});

// دریافت درخواست‌های فعال
app.get("/active-requests", authenticate, async (req, res) => {
  try {
    const requests = await Request.find({ status: "active" });
    res.status(200).json(requests);
  } catch (error) {
    res.status(400).send("Error: " + error.message);
  }
});

// پذیرش درخواست توسط مشاور
app.post("/accept-request", authenticate, async (req, res) => {
  if (req.user.role !== "advisor")
    return res.status(403).send("Only advisors can accept requests");
  const { requestId } = req.body;
  try {
    const request = await Request.findById(requestId);
    if (!request) return res.status(404).send("Request not found");

    request.status = "accepted";
    request.advisorId = req.user.userId;
    await request.save();
    res.status(200).send("Request accepted successfully");
  } catch (error) {
    res.status(400).send("Error: " + error.message);
  }
});

// مشاهده درخواست‌ها توسط ادمین
app.get("/admin-requests", authenticate, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).send("Only admins can view all requests");
  try {
    const requests = await Request.find();
    res.status(200).json(requests);
  } catch (error) {
    res.status(400).send("Error: " + error.message);
  }
});

// شروع سرور
app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});