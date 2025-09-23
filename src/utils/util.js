const { error } = require("console");

const RESPONSE_OBJECT = {
    status:"",
    message:"",
    data:[],
    errorCode:""
}
const getSuccessResponseObject = ( message, data) => {
    RESPONSE_OBJECT.status = "success";
    RESPONSE_OBJECT.message = message;
    RESPONSE_OBJECT.data = data;
    RESPONSE_OBJECT.errorCode = null;
    return RESPONSE_OBJECT;
}
const getFailureResponseObject = ( message, errorCode) => {
    RESPONSE_OBJECT.status = "failure";
    RESPONSE_OBJECT.message = message;
    RESPONSE_OBJECT.data = [];
    RESPONSE_OBJECT.errorCode = errorCode;
    return RESPONSE_OBJECT;
}
const getErrorResponseObject = () => {
    RESPONSE_OBJECT.status = "error";
    RESPONSE_OBJECT.message = "Internal server error";
    RESPONSE_OBJECT.data = null;
    RESPONSE_OBJECT.errorCode = "ERR_INTERNAL_SERVER";
    return RESPONSE_OBJECT;
}

// Generic response property selectors
function getClientResponse(user, properties = ['name', 'mobile']) {
    // Return only specified properties for CLIENT
    if (!user || !properties || !Array.isArray(properties)) return {};
     const responseObj = properties.reduce((obj, key) => {
        if (user.hasOwnProperty(key)) {
            obj[key] = user[key];
        }
        return obj;
    }, {});
    if(user.name && user?.applications?.includes('CLIENT')){
        responseObj.isRegistered = true;
    }
    else{
        responseObj.isRegistered = false;
    }
    return responseObj;
}

function getVendorResponse(user, properties=['location', 'otpExpireTime','otp']) {
    // Remove only specified properties, keep the rest
    if (!user || !Array.isArray(properties)) return {};
    const result = { ...user };
    properties.forEach(key => {
        delete result[key];
    });
    if(user.name && user?.applications?.includes('VENDOR')){
        result.isRegistered = true;
    }
    else{
        result.isRegistered = false;
    }
    return result;
}

module.exports = {
    RESPONSE_OBJECT,
    getSuccessResponseObject,
    getFailureResponseObject,
    getErrorResponseObject,
    getClientResponse,
    getVendorResponse
};