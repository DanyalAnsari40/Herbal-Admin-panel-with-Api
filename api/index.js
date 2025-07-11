const serverless = require('serverless-http');
const app = require('../app.js');

module.exports = serverless(app);
// ALSO add this to support AWS/Lambda style (Vercel likes it too)
module.exports.handler = serverless(app);
