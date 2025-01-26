const morgan = require('morgan');

module.exports = (env) => {
  return env === 'development' ? morgan('dev') : (req, res, next) => next();
};
