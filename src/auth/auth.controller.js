const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticateJWT } = require('./auth.middleware');
const { generateToken } = require('../utils/jwt');
const { createUserInfo, blacklistToken, isTokenBlacklisted } = require('../utils/authUtils');
const AWS = require('aws-sdk');
const { getFailureResponseObject, getSuccessResponseObject, getErrorResponseObject, getClientResponse, getVendorResponse, getCustomerResponse } = require('../utils/util');
const { v4: uuidv4 } = require('uuid');

// Set AWS region
AWS.config.update({ region: process.env.AWS_REGION || 'ap-south-1' });

const router = express.Router();
const dynamoDB = new AWS.DynamoDB.DocumentClient();


router.post('/login-otp', async (req, res) => {
  const { mobileNumber, appType } = req.body;
  if (!appType) {
    const responseObj = getFailureResponseObject('Please send appType', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
    if (!mobileNumber) {
    const responseObj = getFailureResponseObject('Please send mobile number', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  const getParams = {
    TableName: 'user-otp',
    Key: { mobileNumber },
  };

  try {
    const result = await dynamoDB.get(getParams).promise();
    let user = result.Item;
    const userApplication = appType;

    if (!user) {
      // User not registered, create with mobileNumber and appType
      const item = {
        user_id: uuidv4(),
        mobileNumber,
        applications: [userApplication]
      };
      const params = {
        TableName: 'user-otp',
        Item: item,
      };
      await dynamoDB.put(params).promise();
      user = item;
    } else {
      // User exists, check if appType is present
      let applications = user.applications || [];
  
      if (!applications.includes(userApplication)) {
        applications.push(userApplication);
        // Update applications array in DB
        const updateAppParams = {
          TableName: 'user-otp',
          Key: { mobileNumber },
          UpdateExpression: 'set applications = :applications',
          ExpressionAttributeValues: {
            ':applications': applications
          }
        };
        await dynamoDB.update(updateAppParams).promise();
        user.applications = applications;
      }
    }

    // const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const tempOtp = "000000"
    const otpExpireTime = new Date(Date.now() + process.env.OTP_EXPIRATION_TIME * 1000)
      .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // ...existing code for SNS/SES (commented out)

    const updateParams = {
      TableName: 'user-otp',
      Key: { mobileNumber },
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
  const { mobileNumber, otp, appType } = req.query;

  if (!appType) {
    const responseObj = getFailureResponseObject('Please send appType', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
    if (!mobileNumber) {
    const responseObj = getFailureResponseObject('Please send mobile number', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
    if (!otp) {
    const responseObj = getFailureResponseObject('Please send the otp', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }

  const getParams = {
    TableName: 'user-otp',
    Key: { mobileNumber },
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

    const userApplication = appType;
    const applicationsArr = user.applications;
    if (!applicationsArr.includes(userApplication)) {
      const responseObj = getFailureResponseObject('OTP validated', "ERR_DATA_NOT_FOUND");
      return res.status(404).json(responseObj);
    }
    // Update otpVerified array in DB
    let otpVerifiedArr = user.otpVerified || [];
    if (!otpVerifiedArr.includes(userApplication)) {
      otpVerifiedArr.push(userApplication);
      const updateParams = {
        TableName: 'user-otp',
        Key: { mobileNumber },
        UpdateExpression: 'set otpVerified = :otpVerified',
        ExpressionAttributeValues: {
          ':otpVerified': otpVerifiedArr
        }
      };
      await dynamoDB.update(updateParams).promise();
    }

    const token = generateToken({ user });
    let responseData;
    if (userApplication === 'CLIENT') {
      responseData = getClientResponse(user, ['name', 'mobileNumber']);   
    } else {
      responseData = getVendorResponse(user, [ 'otpExpireTime','otp'] );
    }
    responseData.token = token;
    responseData.applications = applicationsArr;
    responseData.otpVerified = otpVerifiedArr;
    if(user.name){
      responseData.isRegistered = true
    }
    else{
      responseData.isRegistered = false
    }
    const responseObj = getSuccessResponseObject("User is verified successfully", [responseData]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

router.post('/user-registration', authenticateJWT, async (req, res) => {
  const {
    user_id,
    appType,
    name,
    mobileNumber,
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

  // List of required fields based on application type
  let requiredFields;
  if (appType === 'CLIENT') {
    requiredFields = ['mobileNumber'];
  } else if (appType === 'CUSTOMER') {
    requiredFields = ['user_id', 'appType', 'name', 'mobileNumber', 'fullAddress'];
  } else {
    requiredFields = [
      'appType',
      'mobileNumber',
      'category',
      'subCetegory',
      'shopName',
      'shopOwnerName',
      'fullAddress',
      'storeGeolocation',
      'gst'
    ];
  }
  // Find missing or empty fields
  const missingFields = requiredFields.filter(field => {
    if (field === 'mobileNumber') {
      return !mobileNumber || mobileNumber.length < 10;
    }
    return !req.body[field] && req.body[field] !== false && req.body[field] !== 0;
  });
  if (missingFields.length > 0) {
    const responseObj = getFailureResponseObject(
      `Missing or invalid fields: ${missingFields.join(', ')}`,
      "ERR_DATA_NOT_FOUND"
    );
    return res.status(400).json(responseObj);
  }
  const userApplication = appType

  try {
    // Always upsert (add/update) fields for the given mobile number
    // Prepare update expression and attribute values
    const updateFields = {
      name,
      email,
      category,
      subCetegory,
      shopName,
      shopOwnerName,
      address,
      location,
      isRegistered:true,
      isGst,
      ...rest
    };
    let updateExpArr = [];
    let expAttrVals = {};
    let expAttrNames = {};
    Object.keys(updateFields).forEach(key => {
      if (updateFields[key] !== undefined) {
        updateExpArr.push(`#${key} = :${key}`);
        expAttrVals[`:${key}`] = updateFields[key];
        expAttrNames[`#${key}`] = key;
      }
    });
    const updateParams = {
      TableName: 'user-otp',
      Key: { mobileNumber },
      UpdateExpression: 'set ' + updateExpArr.join(', '),
      ExpressionAttributeNames: expAttrNames,
      ExpressionAttributeValues: expAttrVals
    };
    await dynamoDB.update(updateParams).promise();
    const getParams = {
      TableName: 'user-otp',
      Key: { mobileNumber },
    };
    const result = await dynamoDB.get(getParams).promise();
    const user = result.Item;

    let responseData;
    let responseObj 
    if (userApplication === 'CLIENT') {
      responseData = getClientResponse(user);
      responseObj = getSuccessResponseObject("User is registered/updated successfully", [responseData]);
    }
    if(userApplication === 'CUSTOMER'){
      responseData = getCustomerResponse(user);
      responseObj = getSuccessResponseObject("Customer is Created/updated successfully", [responseData]);
    }
    else {
      responseData = getVendorResponse(user);//in arr pass what you want hide in response
      getSuccessResponseObject("Vendor is registered/updated successfully", [responseData]);
    }

    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

router.get('/verify-token', authenticateJWT, (req, res) => {
  const appType = req.query.appType;
  if (!appType) {
    const responseObj = getFailureResponseObject('Please send the app type', "ERR_DATA_NOT_FOUND");
    return res.status(401).json(responseObj);
  }
  const user = req.user.user || req.user; // support both {user} and direct user
  const applicationsArr = user.applications;
  if (!applicationsArr || !applicationsArr.includes(appType)) {
    const responseObj = getFailureResponseObject('User is not registered for this application', "ERR_DATA_NOT_FOUND");
    return res.status(404).json(responseObj);
  }
  let responseData;
  if (appType === 'CLIENT') {
    responseData = getClientResponse(user, ['name', 'mobileNumber','otpExpireTime']);
  } else {
    responseData = getVendorResponse(user);
  }
  // responseData.applications = applicationsArr;
  responseData.isTokenVerified = true
  const responseObj = getSuccessResponseObject("Token is valid", responseData);
  res.json(responseObj);
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

// GET /registration-data/:user_id - Requires valid token, returns user data by user_id
router.get('/registration-data/:user_id', authenticateJWT, async (req, res) => {
  const { user_id } = req.params;
  const appType = req.query.appType;
  if (!user_id) {
    const responseObj = getFailureResponseObject('Please provide user_id', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  if (!appType) {
    const responseObj = getFailureResponseObject('Please provide appType in query params', "ERR_DATA_NOT_FOUND");
    return res.status(400).json(responseObj);
  }
  // Scan DynamoDB for user with matching user_id
  const params = {
    TableName: 'user-otp',
    FilterExpression: 'user_id = :user_id',
    ExpressionAttributeValues: {
      ':user_id': user_id
    }
  };
  try {
    const result = await dynamoDB.scan(params).promise();
    if (!result.Items || result.Items.length === 0) {
      const responseObj = getFailureResponseObject('No user found for given user_id', "ERR_DATA_NOT_FOUND");
      return res.status(404).json(responseObj);
    }
    const user = result.Items[0];
    let responseData;
    if (appType === 'CLIENT') {
      responseData = getClientResponse(user);
    } else if (appType === 'VENDOR') {
      responseData = getVendorResponse(user);
    } else {
      const responseObj = getFailureResponseObject('Invalid appType', "ERR_INVALID_APP_TYPE");
      return res.status(400).json(responseObj);
    }
    const responseObj = getSuccessResponseObject('User data fetched successfully', [responseData]);
    res.json(responseObj);
  } catch (error) {
    console.error('DynamoDB Error:', error);
    const responseObj = getErrorResponseObject();
    res.status(500).json(responseObj);
  }
});

module.exports = router;
