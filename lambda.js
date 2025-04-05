const serverlessExpress = require('@vendia/serverless-express');
const app = require('./src/server');
console.log("💡 Lambda handler initialized");
exports.handler = serverlessExpress({ app });
