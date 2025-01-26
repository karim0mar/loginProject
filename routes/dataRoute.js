const express = require('express');
const router = express.Router();
const { getData, getUsers } = require('../contorllers/dataController');
const {protect} = require('../contorllers/authController')

router.get('/', protect, getData);
router.get('/users', protect,getUsers)

module.exports = router;

// server.js
