const serverlessExpress = require('@vendia/serverless-express');
const app = require('./src/server');
exports.handler = serverlessExpress({ app });
