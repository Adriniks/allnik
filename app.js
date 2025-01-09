const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/user");
const advisorRoutes = require("./routes/advisor");
const adminRoutes = require("./routes/admin");
const requestRoutes = require("./routes/request");

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);
app.use("/api/advisor", advisorRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/requests", requestRoutes);

module.exports = app;