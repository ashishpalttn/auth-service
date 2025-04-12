const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateToken } = require('../utils/jwt');
const AWS = require('aws-sdk')

const router = express.Router();
const dynamoDB = new AWS.DynamoDB.DocumentClient();

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to DynamoDB
    const params = {
      TableName: 'Users',
      Item: {
        email,
        password: hashedPassword,
      },
    };
    try {
      await dynamoDB.put(params).promise();
      res.json({ message: 'Registered successfully' });
    } catch (error) {
      console.error('DynamoDB Error:', error);
      res.status(500).json({ error: 'Could not register user' });
    }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
    // Retrieve user from DynamoDB
    const params = {
      TableName: 'Users',
      Key: { email },
    };


    try {
      const result = await dynamoDB.get(params).promise();
      const user = result.Item;
  
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Compare passwords
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Generate JWT token
      const token = generateToken({ email });
      res.json({ token });
    } catch (error) {
      console.error('DynamoDB Error:', error);
      res.status(500).json({ error: 'Could not log in user' });
    }
});

module.exports = router;



//  curl -X POST http://localhost:4000/auth/register   -H "Content-Type: applicatio
// n/json"   -d '{"email": "testuser@example.com", "password": "Test@1234"}'