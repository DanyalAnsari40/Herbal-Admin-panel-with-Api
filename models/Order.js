const mongoose = require("mongoose");

const landingOrderSchema = new mongoose.Schema({
  name: String,
  phone: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  isInProgress: { type: Boolean, default: false },
  handledBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee' },
  review: { type: String }, // Add this line
  callStatus: {
  type: String,
  enum: ['Answered', 'Declined', 'Pending'],
  default: 'Pending'
}

});

module.exports = mongoose.model("LandingOrder", landingOrderSchema);
