const serverless = require('serverless-http');
const app = require('../app.js');

console.log("🚀 api/index.js loaded");

module.exports = serverless(app);
module.exports.handler = serverless(app); // IMPORTANT for Vercel
