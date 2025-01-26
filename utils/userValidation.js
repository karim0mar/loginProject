const bcrypt = require('bcryptjs');
const User = require('../models/userModel');

async function validateUser(username, password) {
    const user = await User.findOne({ username }).select('username +password role active accessToken');
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return null;
    }
    return user;
}

module.exports = validateUser;
