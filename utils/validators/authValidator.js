const { check } = require('express-validator');
const validatorMiddleware = require('../../middlewares/validatorMiddleware');

const loginValidator = [
    check('username').notEmpty().withMessage('Username required'),
    check('password').notEmpty().withMessage('Password required')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters'),
    validatorMiddleware,
];
module.exports = {loginValidator};