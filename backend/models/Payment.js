// const mongoose = require('mongoose');

// // Define Payment schema
// const paymentSchema = new mongoose.Schema({
//   paymentId: { 
//     type: String, 
//     required: true, 
//     unique: true // Ensures paymentId is unique
//   },
//   orderId: { 
//     type: String, 
//     required: true 
//   },
//   amount: { 
//     type: Number, 
//     required: true,
//     min: 0 // Ensures no negative amounts
//   },
//   currency: { 
//     type: String, 
//     required: true,
//     trim: true // Removes unnecessary whitespace
//   },
//   name: { 
//     type: String, 
//     required: true,
//     trim: true 
//   },
//   items: { 
//     type: [String], 
//     required: true 
//   },
//   tableNumber: { 
//     type: String, 
//     required: true,
//     trim: true 
//   },
//   token: { 
//     type: String, 
//     required: true,
//     trim: true 
//   },
//   status: { 
//     type: String, 
//     required: true, 
//     enum: ['Pending', 'Completed', 'Failed'], 
//     default: 'Pending' 
//   },
//   date: { 
//     type: Date, 
//     default: Date.now 
//   }
// }, { 
//   timestamps: true // Automatically adds createdAt and updatedAt fields
// });

// // Create Payment model
// const Payment = mongoose.model('Payment', paymentSchema);

// module.exports = Payment;
