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
    return properties.reduce((obj, key) => {
        if (user.hasOwnProperty(key)) {
            obj[key] = user[key];
        }
        return obj;
    }, {});
}

function getVendorResponse(user) {
    // Return all properties for VENDOR, but you can customize here
    // For now, return the whole user object
    return { ...user };
}

module.exports = {
    RESPONSE_OBJECT,
    getSuccessResponseObject,
    getFailureResponseObject,
    getErrorResponseObject,
    getClientResponse,
    getVendorResponse
};