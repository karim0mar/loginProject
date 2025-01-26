const Data = require('../models/dataModel');
const User = require('../models/userModel');

const asyncHandler = require('express-async-handler');

const getData = asyncHandler(async (req, res) => {
    const data = await Data.find({}).select('secure_text -_id');
    res.status(200).json({ data });
});
const getUsers = asyncHandler(async (req, res) => {
    const data = await User.find({});
    res.status(200).json({ data });
});
module.exports = {getData , getUsers    };