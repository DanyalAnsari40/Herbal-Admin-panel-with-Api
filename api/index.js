const serverless = require('serverless-http');
const app = require('../app.js');

module.exports = serverless(app);
