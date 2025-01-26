const express = require('express');
const {login,refresh} = require("../contorllers/authController");
const {loginValidator} = require('../utils/validators/authValidator')
const router = express.Router();

router.route('/').post(...loginValidator,login);

router.route('/refresh').post(refresh);

module.exports = router;