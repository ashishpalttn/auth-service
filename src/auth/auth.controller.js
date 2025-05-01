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



router.post('/signup-otp', async (req, res) => {
  const {name, mobile, email, } = req.body;

    const getParams = {
      TableName: 'user-otp',
      Key:{ mobile },
    }

    const params = {
      TableName: 'user-otp',
      Item: {
        name,
        mobile,
        email,  
      },
    };
    try {
      const isUserExists = await dynamoDB.get(getParams).promise();
      if (isUserExists.Item) {
        return res.status(409).json({ error: 'User already exists' });
      }
      await dynamoDB.put(params).promise();
      res.json({ message: 'Signup successfully done' });
    } catch (error) {
      console.error('DynamoDB Error:', error);
      res.status(500).json({ error: 'mobile no. is required' });
    }
});

router.post('/login-otp', async (req, res) => {
  console.log("login-otp triggered");
  const { mobile } = req.body;

  // Check if mobile exists in Users table
  const getParams = {
    TableName: 'user-otp',
    Key: { mobile },
  };

  try {
    const result = await dynamoDB.get(getParams).promise();
    const user = result.Item;

    if (!user) {
      return res.status(404).json({ error: 'User is not registered' });
    }
    console.log("number is found", user);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Calculate OTP expiration time (10 minutes from now) in IST
    const otpExpireTime = new Date(Date.now() + 10 * 60 * 1000)
      .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // Send OTP using AWS SNS
    const sns = new AWS.SNS();
    const snsParams = {
      Message: `Your live bazar login OTP is- ${otp}`,
      PhoneNumber: `+91${mobile}`,
    };

    console.log("SNS Params:", snsParams); // Log SNS parameters

    try {
      const snsResponse = await sns.publish(snsParams).promise();
      console.log("SNS Response:", snsResponse); // Log SNS response
    } catch (snsError) {
      console.error("SNS Error:", snsError); // Log SNS error
      return res.status(500).json({ error: 'Failed to send OTP via SMS' });
    }

    // Send OTP via email if email exists
    if (user.email) {
      const ses = new AWS.SES();
      const emailParams = {
        Source: process.env.SES_EMAIL_SOURCE, // Set your verified SES email
        Destination: {
          ToAddresses: [user.email],
        },
        Message: {
          Subject: {
            Data: "Your Live Bazar OTP",
          },
          Body: {
            Text: {
              Data: `Your live bazar login OTP is- ${otp}`,
            },
          },
        },
      };

      try {
        const emailResponse = await ses.sendEmail(emailParams).promise();
        console.log("Email Response:", emailResponse); // Log email response
      } catch (emailError) {
        console.error("Email Error:", emailError); // Log email error
        return res.status(500).json({ error: 'Failed to send OTP via email' });
      }
    }

    // Save OTP and expiration time in Users table
    const updateParams = {
      TableName: 'user-otp',
      Key: { mobile },
      UpdateExpression: 'set otp = :otp, otpExpireTime = :otpExpireTime',
      ExpressionAttributeValues: {
        ':otp': otp,
        ':otpExpireTime': otpExpireTime,
      },
    };

    await dynamoDB.update(updateParams).promise();

    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('DynamoDB or SNS Error:', error);
    res.status(500).json({ error: 'Could not process login OTP' });
  }
});

router.get('/verify-otp', async (req, res) => {
  const { mobile, otp } = req.query;

  // Check if mobile and OTP exist in Users table
  const getParams = {
    TableName: 'user-otp',
    Key: { mobile },
  };

  try {
    const result = await dynamoDB.get(getParams).promise();
    const user = result.Item;

    if (!user) {
      return res.status(404).json({ error: 'User is not registered' });
    }

    if (user.otp !== otp) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    // Generate JWT token
    const token = generateToken({ mobile });
    const userInfo = Object.keys(user)
      .filter(key => key !== 'otp' && key !== 'otpExpireTime')
      .reduce((obj, key) => {
        obj[key] = user[key];
        return obj;
      }, {});
    res.json({ token,userInfo });
  } catch (error) {
    console.error('DynamoDB Error:', error);
    res.status(500).json({ error: 'Could not verify OTP' });
  }
})

router.get('/verify-token', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    res.json({isVerified : true, message: 'Token is valid', decoded });
  });
});

router.get('/logout', (req, res) => {
  // Invalidate the token by removing it from the client side
  res.json({ message: 'Logged out successfully' });
});



module.exports = router;
