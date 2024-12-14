const bcrypt = require('bcryptjs');

// Sample password
const password = 'password123';
const hashedPassword = '$2a$10$K/7hjSjusN9C6U1xgXzHLOv31GdN9r.Lvzr39pLZL90QX3Axuzpba'; // Use the hash from your DB

bcrypt.compare(password, hashedPassword, (err, result) => {
  if (err) {
    console.log("Error:", err);
  } else {
    console.log("Do the passwords match?", result); // Should print true if they match
  }
});
