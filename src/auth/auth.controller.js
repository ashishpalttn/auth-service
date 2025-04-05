const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateToken } = require('../utils/jwt');

const router = express.Router();
const users = []; // In-memory for demo

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });
  res.json({ message: 'Registered successfully' });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = generateToken({ email });
  res.json({ token });
});

module.exports = router;



//  curl -X POST http://localhost:4000/auth/register   -H "Content-Type: applicatio
// n/json"   -d '{"email": "testuser@example.com", "password": "Test@1234"}'