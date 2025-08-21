const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateToken } = require('../utils/jwt');
const { createUserInfo, blacklistToken, isTokenBlacklisted } = require('../utils/authUtils');
const AWS = require('aws-sdk');
const { getFailureResponseObject, getSuccessResponseObject, getErrorResponseObject, getClientResponse, getVendorResponse } = require('../utils/util');

// Set AWS region
AWS.config.update({ region: process.env.AWS_REGION || 'ap-south-1' });

const router = express.Router();
const dynamoDB = new AWS.DynamoDB.DocumentClient();

// router.post('/register', async (req, res) => {
//   const { email, password } = req.body;
//   const hashedPassword = await bcrypt.hash(password, 10);
//   const params = {
//     TableName: 'Users',
//     Item: {
//       email,
//       password: hashedPassword,
//     },
//   };
//   try {
//     await dynamoDB.put(params).promise();
//     const responseObj = getSuccessResponseObject("User is registered successfully", [req.body]);
//     res.json(responseObj);
//   } catch (error) {
//     console.error('DynamoDB Error:', error);
//     responseObj = getErrorResponseObject();
//     res.status(500).json(responseObj);
//   }
// });

// router.post('/login', async (req, res) => {
//   const { email, password } = req.body;
//   const params = {
//     TableName: 'Users',
//     Key: { email },
//   };
//   try {
//     const result = await dynamoDB.get(params).promise();
//     const user = result.Item;
//     if (!user) {
//       const responseObj = getFailureResponseObject('User not found', "ERR_DATA_NOT_FOUND");
//       return res.status(401).json(responseObj);
//     }
//     const match = await bcrypt.compare(password, user.password);
//     if (!match) {
//       const responseObj = getFailureResponseObject('Invalid credentials', "ERR_DATA_NOT_FOUND");
//       return res.status(401).json(responseObj);
//     }
//     const token = generateToken({ email });
//     const userInfo = createUserInfo(user);
//     const responseObj = getSuccessResponseObject("User is logged in successfully", [{ token }, userInfo]);
//     res.json(responseObj);
//   } catch (error) {
//     console.error('DynamoDB Error:', error);
//     const responseObj = getErrorResponseObject();
//     res.status(500).json(responseObj);
//   }
// });





router.post('/signup-otp', async (req, res) => {
  const {
    application,
    name,
    mobile,
    category,
    subCetegory,
    shopName,
    shopOwnerName,
    address,
    location,
    email,
    isGst,
    ...rest
  } = req.body;

  if (!mobile || mobile.length < 10) {
    const responseObj = getFailureResponseObject('Invalid mobile number', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  if (!name) {
    const responseObj = getFailureResponseObject('name is required', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  const userApplication = application === 'VENDOR' ? 'VENDOR' : 'CLIENT';
  const getParams = {
    TableName: 'user-otp',
    Key: { mobile },
  };
  try {
    const isUserExists = await dynamoDB.get(getParams).promise();
    if (isUserExists.Item) {
      // User exists, check applications
      let applications = isUserExists.Item.applications || isUserExists.Item.roles || [];
      // For backward compatibility, check if single role exists
      if (isUserExists.Item.role && !applications.includes(isUserExists.Item.role)) {
        applications.push(isUserExists.Item.role);
      }
      if (applications.includes(userApplication)) {
        const responseObj = getFailureResponseObject('User already exists with this application', "ERR_DATA_NOT_FOUND");
        return res.status(409).json(responseObj);
      }
      // Add new application to applications array
      applications.push(userApplication);
      // Only update name if provided, keep other fields unchanged
      let updateExp = '#applications = :applications';
      let updateFields = {
        '#applications': 'applications'
      };
      let expAttrVals = {
        ':applications': applications
      };
      if (name) {
        updateFields['#name'] = 'name';
        updateExp = '#name = :name, ' + updateExp;
        expAttrVals[':name'] = name;
      }
      // Only add #location if location is being updated (not in this logic)

      const updateParams = {
        TableName: 'user-otp',
        Key: { mobile },
        UpdateExpression: 'set ' + updateExp,
        ExpressionAttributeNames: updateFields,
        ExpressionAttributeValues: expAttrVals
      };
      await dynamoDB.update(updateParams).promise();
      // Compose response with updated applications and name, rest fields from DB
      let updatedUser = { ...isUserExists.Item, applications };
      if (name) {
        updatedUser.name = name;
      }
      let responseData;
      if (userApplication === 'CLIENT') {
        responseData = getClientResponse(updatedUser);
      } else {
        responseData = getVendorResponse(updatedUser);
      }
      const responseObj = getSuccessResponseObject("Application added successfully", [responseData]);
      return res.json(responseObj);
    }
    // User does not exist, create with single application
    const item = {
      name,
      mobile,
      email,
      applications: [userApplication],
      category,
      subCetegory,
      shopName,
      shopOwnerName,
      address,
      location,
      isGst,
      ...rest
    };
    const params = {
      TableName: 'user-otp',
      Item: item,
    };
    await dynamoDB.put(params).promise();
    let responseData;
    if (userApplication === 'CLIENT') {
      responseData = getClientResponse(item);
    } else {
      responseData = getVendorResponse(item);
    }
    const responseObj = getSuccessResponseObject("User is registered successfully", [responseData]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});


router.post('/login-otp', async (req, res) => {
  const { mobile, application } = req.body;
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
    // Check if application exists for user
    const applications = user.applications || user.roles || (user.role ? [user.role] : []);
    if (!applications.includes(application)) {
      const responseObj = getFailureResponseObject('User is not registered for this application', "ERR_DATA_NOT_FOUND");
      return res.status(404).json(responseObj);
    }
    // const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const tempOtp = "000000"
    const otpExpireTime = new Date(Date.now() + process.env.OTP_EXPIRATION_TIME * 1000)
      .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // ...existing code for SNS/SES (commented out)

    const updateParams = {
      TableName: 'user-otp',
      Key: { mobile },
      UpdateExpression: 'set otp = :otp, otpExpireTime = :otpExpireTime',
      ExpressionAttributeValues: {
        ':otp': tempOtp,
        ':otpExpireTime': otpExpireTime,
      },
    };

    await dynamoDB.update(updateParams).promise();
    const responseObj = getSuccessResponseObject("OTP sent successfully", [req.body]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB or SNS Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});




router.get('/verify-otp', async (req, res) => {
  const { mobile, otp, application } = req.query;

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

    const userApplication = (application === 'VENDOR') ? 'VENDOR' : 'CLIENT';
    const applicationsArr = user.applications || user.roles || (user.role ? [user.role] : ['CLIENT']);
    if (!applicationsArr.includes(userApplication)) {
      const responseObj = getFailureResponseObject('User is not registered for this application', "ERR_DATA_NOT_FOUND");
      return res.status(404).json(responseObj);
    }
    const token = generateToken({ user });
    let responseData;
    if (userApplication === 'CLIENT') {
      responseData = getClientResponse(user, ['name', 'mobile', 'otpExpireTime']);
    } else {
      responseData = getVendorResponse(user);
    }
    responseData.token = token;
    responseData.applications = applicationsArr;
    const responseObj = getSuccessResponseObject("User is verified successfully", [responseData]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});



router.get('/verify-token', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  const application = (req.query.application === 'VENDOR') ? 'VENDOR' : 'CLIENT';

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
    const user = decoded.user;
    let responseData;
    if (application === 'CLIENT') {
      responseData = getClientResponse(user, properties = ['name', 'mobile','otpExpireTime']);
    } else {
      responseData = getVendorResponse(user);
    }
    responseData.applications = user.applications || user.roles || (user.role ? [user.role] : ['CLIENT']);
    const responseObj = getSuccessResponseObject("Token is valid", [responseData]);
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
