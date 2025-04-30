const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateToken } = require('../utils/jwt');
const AWS = require('aws-sdk');

// Set AWS region
AWS.config.update({ region: process.env.AWS_REGION || 'ap-south-1' });

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
      res.json({ message: 'Registered successfully done' });
    } catch (error) {
      console.error('DynamoDB Error:', error);
      res.status(500).json({ error: 'Could not register user' });
    }
});

router.post('/signup', async (req, res) => {
  const {name, mobile, email, } = req.body;

    // Save user to DynamoDB
    const params = {
      TableName: 'Users',
      Item: {
        name,
        mobile,
        email,  
      },
    };
    try {
      await dynamoDB.put(params).promise();
      res.json({ message: 'Signup successfully done' });
    } catch (error) {
      console.error('DynamoDB Error:', error);
      res.status(500).json({ error: 'Could not register user' });
    }
});

router.post('/login', async (req, res) => {
  // const sns = new AWS.SNS();
  // const  phoneNumber  = 9918434680;
  // const otp = Math.floor(100000 + Math.random() * 900000);
  // const sendOTP = async (phoneNumber, otp) => {
  //   const params = {
  //     Message: `Your OTP is ${otp}`,
  //     PhoneNumber: phoneNumber, // in E.164 format, e.g., +911234567890
  //   };
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