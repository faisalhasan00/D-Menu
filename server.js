require('dotenv').config(); 
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const Joi = require('joi');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const menuRoutes = require('./backend/routes/menuRoute');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;

// Validate environment variables
if (!JWT_SECRET || !MONGODB_URI) {
    console.error("Error: Missing environment variables.");
    process.exit(1);
}

// Connect to MongoDB
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch(err => {
        console.error("MongoDB connection error:", err);
        process.exit(1);
    });

// CORS Configuration
const whitelist = process.env.NODE_ENV === 'production' 
    ? ['https://your-production-site.com'] 
    : ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://127.0.0.1:5501'];

const corsOptions = {
    origin: whitelist,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

// Middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
});
app.use(limiter);

// Static file serving
app.use(express.static(path.join(__dirname, 'frontend')));

// Models
const User = mongoose.model("User", new mongoose.Schema({
    fullname: String,
    email: { type: String, unique: true },
    phone: { type: String, unique: true },
    password: String,
    restaurantName: String,
    restaurantId: { type: String, unique: true },
    state: String,
    district: String,
    city: String,
    pincode: String,
}));

const Order = mongoose.model('Order', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    items: [{ type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem' }],
    totalAmount: Number,
    status: { type: String, default: 'Pending' },
    date: { type: Date, default: Date.now },
}, { timestamps: true }));

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized: No token provided.' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized: No token found.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Forbidden: Invalid token.' });
        req.user = decoded;
        next();
    });
};

// Fetch Orders Route
app.get('/api/orders', authenticateJWT, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.user.id });
        res.status(200).json(orders);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch orders.' });
    }
});

// Register
app.post('/register', async (req, res) => {
    const schema = Joi.object({
        fullname: Joi.string().required(),
        email: Joi.string().email().required(),
        phone: Joi.string().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({
            "any.only": "Passwords do not match."
        }),
        restaurantName: Joi.string().required(),
        state: Joi.string().required(),
        district: Joi.string().required(),
        city: Joi.string().required(),
        pincode: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const { fullname, email, phone, password, restaurantName, state, district, city, pincode } = req.body;

    try {
        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
        if (existingUser) return res.status(400).json({ error: "User with this email or phone already exists." });

        const hashedPassword = bcrypt.hashSync(password, 10);
        const restaurantId = `${restaurantName}-${Date.now()}`;
        const user = new User({ fullname, email, phone, password: hashedPassword, restaurantName, restaurantId, state, district, city, pincode });
        await user.save();

        res.status(201).json({ message: "User registered successfully.", restaurantId });
    } catch (err) {
        res.status(500).json({ error: "Internal server error." });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { phone, password } = req.body;
    try {
        const user = await User.findOne({ phone });
        if (!user) return res.status(400).json({ error: "User not found." });

        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials." });

        const token = jwt.sign({ id: user._id, restaurantId: user.restaurantId }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: "Login successful.", token, restaurantId: user.restaurantId });
    } catch (err) {
        res.status(500).json({ error: "Internal server error." });
    }
});

// Razorpay integration
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

app.post('/api/payment/order', authenticateJWT, async (req, res) => {
    const { amount, receipt } = req.body;
    try {
        const options = { amount: amount * 100, currency: 'INR', receipt, payment_capture: 1 };
        const order = await razorpay.orders.create(options);
        res.status(200).json(order);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create payment order.' });
    }
});

// Orders Routes
app.post('/api/orders', authenticateJWT, async (req, res) => {
    const { items, totalAmount } = req.body;
    try {
        const newOrder = new Order({ userId: req.user.id, items, totalAmount, status: 'Pending' });
        await newOrder.save();
        res.status(201).json(newOrder);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create order.' });
    }
});

// Menu Routes
app.use('/api/menu', authenticateJWT, menuRoutes);

// Serve Pages
app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'frontend', 'index.html'));
});

// Start the server
app.listen(PORT, () => console.log(`Server running on http://127.0.0.1:${PORT}`));
