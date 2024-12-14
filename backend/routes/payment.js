// const express = require('express');
// const Payment = require('../models/Payment');
// const Joi = require('joi');

// const router = express.Router();

// // Joi Schema for Validation
// const paymentSchema = Joi.object({
//   paymentId: Joi.string().required(),
//   orderId: Joi.string().required(),
//   amount: Joi.number().positive().required(),
//   currency: Joi.string().required(),
//   name: Joi.string().required(),
//   items: Joi.array().items(Joi.object()).required(),
//   tableNumber: Joi.number().integer().positive().required(),
//   token: Joi.string().optional(),
// });

// // Create a new payment entry
// router.post('/', async (req, res) => {
//   const { error } = paymentSchema.validate(req.body);

//   if (error) {
//     return res.status(400).json({ message: 'Validation error', details: error.details });
//   }

//   const { paymentId, orderId, amount, currency, name, items, tableNumber, token } = req.body;

//   try {
//     const payment = new Payment({
//       paymentId,
//       orderId,
//       amount,
//       currency,
//       name,
//       items,
//       tableNumber,
//       token,
//     });

//     await payment.save();
//     res.status(201).json({ message: 'Payment recorded successfully!' });
//   } catch (error) {
//     console.error('Error creating payment:', error);
//     res.status(500).json({ message: 'Error creating payment entry', error: error.message });
//   }
// });

// module.exports = router;
