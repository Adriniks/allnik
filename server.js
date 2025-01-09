const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// اتصال به دیتابیس MongoDB
mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/allnik", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// مدل‌های دیتابیس
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" }, // "user" یا "advisor"
});
const RequestSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  description: String,
  status: { type: String, default: "active" }, // "active" یا "accepted"
  advisorId: mongoose.Schema.Types.ObjectId,
});
const User = mongoose.model("User", UserSchema);
const Request = mongoose.model("Request", RequestSchema);

// ثبت‌نام
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).send("User registered successfully");
  } catch (error) {
    res.status(400).send("Error: " + error.message);
  }
});

// ورود
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
app.post("/create-request", async (req, res) => {
  const { token, description } = req.body;
  try {
    const decoded = jwt.verify(token, "secret_key");
    const request = new Request({ userId: decoded.userId, description });
    await request.save();
    res.status(201).send("Request created successfully");
  } catch (error) {
    res.status(401).send("Unauthorized");
  }
});

// نمایش درخواست‌های فعال
app.get("/active-requests", async (req, res) => {
  const requests = await Request.find({ status: "active" }).populate("userId");
  res.status(200).json(requests);
});

// پذیرش درخواست توسط مشاور
app.post("/accept-request", async (req, res) => {
  const { token, requestId } = req.body;
  try {
    const decoded = jwt.verify(token, "secret_key");
    if (decoded.role !== "advisor")
      return res.status(403).send("Only advisors can accept requests");

    const request = await Request.findById(requestId);
    if (!request) return res.status(404).send("Request not found");

    request.status = "accepted";
    request.advisorId = decoded.userId;
    await request.save();
    res.status(200).send("Request accepted successfully");
  } catch (error) {
    res.status(401).send("Unauthorized");
  }
});

// شروع سرور
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});