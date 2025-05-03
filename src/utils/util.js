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

module.exports = { RESPONSE_OBJECT,getSuccessResponseObject,getFailureResponseObject ,getErrorResponseObject }; 