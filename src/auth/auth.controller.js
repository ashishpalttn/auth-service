const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateToken } = require('../utils/jwt');
const { createUserInfo, blacklistToken, isTokenBlacklisted } = require('../utils/authUtils');
const AWS = require('aws-sdk');
const { getFailureResponseObject, getSuccessResponseObject, getErrorResponseObject } = require('../utils/util');

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
    const responseObj = getSuccessResponseObject("User is registered successfully", [req.body]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const params = {
    TableName: 'Users',
    Key: { email },
  };
  try {
    const result = await dynamoDB.get(params).promise();
    const user = result.Item;
    if (!user) {
      const responseObj = getFailureResponseObject('User not found', "ERR_DATA_NOT_FOUND");
      return res.status(401).json(responseObj);
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      const responseObj = getFailureResponseObject('Invalid credentials', "ERR_DATA_NOT_FOUND");
      return res.status(401).json(responseObj);
    }
    const token = generateToken({ email });
    const userInfo = createUserInfo(user);
    const responseObj = getSuccessResponseObject("User is logged in successfully", [{ token }, userInfo]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

router.post('/signup-otp', async (req, res) => {
  const { name, mobile, email } = req.body;
  if (!mobile && mobile.length < 10) {
    const responseObj = getFailureResponseObject('Invelid mobile number', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  if (!name) {
    const responseObj = getFailureResponseObject('name is required', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  const getParams = {
    TableName: 'user-otp',
    Key: { mobile },
  };
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
      const responseObj = getFailureResponseObject('User already exists', "ERR_DATA_NOT_FOUND");
      return res.status(409).json(responseObj);
    }
    await dynamoDB.put(params).promise();
    const responseObj = getSuccessResponseObject("User is registered successfully", [req.body]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

router.post('/login-otp', async (req, res) => {
  const { mobile } = req.body;
  const getParams = {
    TableName: 'user-otp',
    Key: { mobile },
  };

  try {
    const result = await dynamoDB.get(getParams).promise();
    const user = result.Item;
    if (!user) {
      const responseObj = getFailureResponseObject('User is not registered', "ERR_DATA_NOT_FOUND");
      return res.status(404).json(responseObj);
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpireTime = new Date(Date.now() + process.env.OTP_EXPIRATION_TIME * 1000)
      .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    const sns = new AWS.SNS();
    const snsParams = {
      Message: `Your live bazar login OTP is- ${otp}`,
      PhoneNumber: `+91${mobile}`,
    };

    try {
      const snsResponse = await sns.publish(snsParams).promise();
      console.log("Otp send success......., SNS Response:", snsResponse);
    } catch (snsError) {
      console.error("SNS Error:", snsError);
      const responseObj = getErrorResponseObject();
      return res.status(500).json(responseObj);
    }
    // if (user.email) {
    //   const ses = new AWS.SES();
    //   const emailParams = {
    //     Source: process.env.SES_EMAIL_SOURCE, // Set your verified SES email
    //     Destination: {
    //       ToAddresses: [user.email],
    //     },
    //     Message: {
    //       Subject: {
    //         Data: "Your Live Bazar OTP",
    //       },
    //       Body: {
    //         Text: {
    //           Data: `Your live bazar login OTP is- ${otp}`,
    //         },
    //       },
    //     },
    //   };

    //   try {
    //     const emailResponse = await ses.sendEmail(emailParams).promise();
    //   } catch (emailError) {
    //     console.error("Email Error:", emailError);
    //     const responseObj = getErrorResponseObject();
    //     return res.status(500).json(responseObj);
    //   }
    // }

    const updateParams = {
      TableName: 'user-otp',
      Key: { mobile },
      UpdateExpression: 'set otp = :otp, otpExpireTime = :otpExpireTime',
      ExpressionAttributeValues: {
        ':otp': otp,
        ':otpExpireTime': otpExpireTime,
      },
    };

    // await dynamoDB.update(updateParams).promise();
    const responseObj = getSuccessResponseObject("OTP sent successfully", [req.body]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB or SNS Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});


router.get('/verify-otp', async (req, res) => {
  const { mobile, otp } = req.query;

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
      const responseObj = getFailureResponseObject('Invalid OTP', "ERR_DATA_NOT_FOUND");
      return res.status(401).json(responseObj);
    }

    const token = generateToken({ user });
    const userInfo = createUserInfo(user);
    const responseObj = getSuccessResponseObject("User is verified successfully", [{ token: token }, userInfo]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

router.get('/verify-token', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    const responseObj = getFailureResponseObject('No token provided', "ERR_DATA_NOT_FOUND");
    return res.status(401).json(responseObj);
  }

  if (isTokenBlacklisted(token)) {
    const responseObj = getFailureResponseObject('Token is blacklisted', "ERR_TOKEN_BLACKLISTED");
    return res.status(401).json(responseObj);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      const responseObj = getFailureResponseObject('Invalid token', "ERR_DATA_NOT_FOUND");
      return res.status(401).json(responseObj);
    }
    const userInfo = createUserInfo(decoded.user);
    const responseObj = getSuccessResponseObject("Token is valid", [userInfo]);
    res.json(responseObj);
  });
});

router.get('/logout-otp', (req, res) => {

  const token = req.headers['authorization']?.split(' ')[1];
  if (token) {
    blacklistToken(token);
  }
  res.clearCookie('token'); 
  const responseObj = getSuccessResponseObject("User is logged out successfully", []);
  res.json(responseObj);
});

module.exports = router;
