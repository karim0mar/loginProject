const ApiError = require('../utils/appError');

const sendErrorForDev = (err, res) =>
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });


const sendErrorForProd = (err, res) =>
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
  });

const handleJwtInvalidSignature = () =>
  new ApiError('Invalid token, please login again..', 401,'fail');

const handleJwtExpired = () =>
  new ApiError('Expired token, please login again..', 401,'fail');

const handleMongoError = (err) => {
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return new ApiError(`Validation error: ${messages.join(', ')}`, 400);
  }

  if (err.code === 11000) {
    return new ApiError('Duplicate field value entered.', 400);
  }

  return new ApiError('Database error occurred.', 500);
};

const globalError = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  if (process.env.NODE_ENV === 'development') {
    sendErrorForDev(err, res);
  } else {
    if (err.name === 'JsonWebTokenError') err = handleJwtInvalidSignature();
    if (err.name === 'TokenExpiredError') err = handleJwtExpired();
    if (err.name === 'ValidationError' || err.code === 11000) err = handleMongoError(err);
    sendErrorForProd(err, res);
  }
};

module.exports = globalError;
