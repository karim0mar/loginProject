const crypto = require('crypto');

function verifySignature(data, signature, secretKey) {
    const computedSignature = crypto
        .createHmac('sha256', secretKey)
        .update(data, 'utf-8')
        .digest('base64');
    return computedSignature === signature;
}

module.exports = verifySignature;
