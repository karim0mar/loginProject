const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate a JWT token
function generateToken(userId, secretKey, expiresIn) {
    return jwt.sign({ UserId: userId }, secretKey, { expiresIn });
}
function generateSecureKeys(){
// Generate a strong random secret key
let secretKey = crypto.randomBytes(64).toString('hex');
console.log("Generated access JWT Secret Key:", secretKey);
secretKey = crypto.randomBytes(64).toString('hex');
console.log("Generated refresh JWT Secret Key:", secretKey);
}
module.exports = { generateToken , generateSecureKeys };
