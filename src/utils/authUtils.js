const createUserInfo = (user) => {
  const userInfo = Object.keys(user)
  .filter(key => key !== 'otp' && key !== 'otpExpireTime')
  .reduce((obj, key) => {
    obj[key] = user[key];
    return obj;
  }, {});

  return userInfo;
}

module.exports = {createUserInfo}