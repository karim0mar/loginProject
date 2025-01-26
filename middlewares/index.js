const express = require('express');
const cors = require('cors')
const corsConfig = require('../config/corsConfig');
const rateLimitConfig = require('../config/rateLimitConfig');
const morganConfig = require('../config/morganConfig');
const compression = require('compression');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean')
//require('./utils/jwtUtils').generateSecureKeys();

const MountMiddlewares = (app)=> {
    // Middleware setup
app.use(cors(corsConfig)); // CORS config
app.use(compression()); // Compress responses
app.use(morganConfig(process.env.NODE_ENV)); // Morgan logging for dev mode
app.use(rateLimitConfig); // Rate-limiting middleware
app.use(helmet()); // Helmet for security
// Middleware to parse JSON with limit
app.use(express.json({ limit: '20kb' }));

app.use(mongoSanitize());

app.use(xss())

}
module.exports = MountMiddlewares;