const jwt = require('jsonwebtoken'); 
const JWT_SECRET = process.env.JWT_SECRET;

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    // Extract the token from the Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];  // Expected format: "Bearer <token>"
    
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: No token provided.' });
    }

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err.message);  // Log the error for debugging
            return res.status(403).json({ error: 'Forbidden: Invalid or expired token.' });
        }

        req.user = user;  // Attach the decoded user information to the request object
        next();  // Proceed to the next middleware or route handler
    });
};

module.exports = authenticateJWT;
