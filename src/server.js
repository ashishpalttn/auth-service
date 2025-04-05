require('dotenv').config();
const express = require('express');
const app = express();
const authRoutes = require('./auth/auth.controller');
const { authenticateJWT } = require('./auth/auth.middleware');

app.use(express.json());

// Public Routes
app.use('/auth', authRoutes);

// Protected Route
app.get('/protected', authenticateJWT, (req, res) => {
  res.json({ message: `Hello ${req.user.email}, this is protected content.` });
});

// For local testing
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
}

module.exports = app;
