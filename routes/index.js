// routes/mountRoutes.js
const authRoute = require('./authRoute');
const dataRoute = require('./dataRoute');

const mountRoutes = (app) => {
  // Mount routes here
  app.use('/auth', authRoute);
  app.use('/data', dataRoute);
};

module.exports = mountRoutes;
