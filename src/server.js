require('dotenv').config();
const express = require('express');
const app = express();

const authRoutes = require('./auth/auth.controller');
const { authenticateJWT } = require('./auth/auth.middleware');

app.use(express.json());

app.use((req, res, next) => {
    console.log(`📥 Incoming request: ${req.method} ${req.originalUrl}`);
    next();
});

// Health check route
app.get("/", (req, res) => {
  res.send("✅ Lambda is working 🚀");
});

app.get("/default", (req, res) => {
    res.send("✅ default route check🚀");
  });

  app.get("/verify", (req, res) => {
    res.send("✅ verify route check🚀");
  });

// Public routes
app.use('/auth', authRoutes);

// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
  res.json({ message: `Hello ${req.user.email}, this is protected content.` });
});

// Catch-all for unknown routes (404)
app.use("*", (req, res) => {
  res.status(404).json({ message: `Route ${req.originalUrl} not found` });
});

// Global error handler middleware
app.use((err, req, res, next) => {
  console.error("💥 Express Error:", err);
  res.status(500).json({
    message: 'Something broke!',
    error: err.message,
    stack: process.env.NODE_ENV === 'production' ? '🥷' : err.stack
  });
});

// Local testing only
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => console.log(`🟢 Listening on port ${PORT}`));
}

module.exports = app;
