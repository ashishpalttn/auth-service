const jwt = require('jsonwebtoken');
const { getFailureResponseObject } = require('../utils/util');

function authenticateJWT(req, res, next) {
  let token;
  // Try Authorization header first
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }
  // Fallback to cookie (token=...)
  if (!token && req.headers.cookie) {
    // Parse cookie string for token
    const match = req.headers.cookie.match(/token=([^;]+)/);
    if (match) {
      token = match[1].replace(/"/g, ''); // Remove quotes if present
    }
  }
  if (!token) {
    const responseObj = getFailureResponseObject('No token provided', 'ERR_NO_TOKEN');
    return res.status(401).json(responseObj);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      let message = 'Invalid or expired token';
      let code = 'ERR_INVALID_TOKEN';
      if (err.name === 'TokenExpiredError') {
        message = 'Token has expired';
        code = 'ERR_TOKEN_EXPIRED';
      }
      const responseObj = getFailureResponseObject(message, code);
      return res.status(401).json(responseObj);
    }
    req.user = user;
    req.token = token;
    next();
  });
}
 
module.exports = { authenticateJWT };
