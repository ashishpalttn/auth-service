const createUserInfo = (user) => {
  const userInfo = Object.keys(user)
  .filter(key => key !== 'otp' && key !== 'otpExpireTime')
  .reduce((obj, key) => {
    obj[key] = user[key];
    return obj;
  }, {});

  return userInfo;
}

const blacklist = new Set();

/**
 * Adds a token to the blacklist.
 * @param {string} token - The JWT token to blacklist.
 */
function blacklistToken(token) {
  blacklist.add(token);
}

/**
 * Checks if a token is blacklisted.
 * @param {string} token - The JWT token to check.
 * @returns {boolean} - True if the token is blacklisted, false otherwise.
 */
function isTokenBlacklisted(token) {
  return blacklist.has(token);
}

module.exports = {
  createUserInfo,
  blacklistToken,
  isTokenBlacklisted,
};