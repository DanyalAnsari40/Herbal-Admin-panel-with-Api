const mongoose = require('mongoose');

const financeSchema = new mongoose.Schema({
  type: { type: String, enum: ['order', 'expense', 'revenue'], required: true },
  description: { type: String, required: true },
  cost: { type: Number, default: 0 },
  revenue: { type: Number, default: 0 },
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Finance', financeSchema);
