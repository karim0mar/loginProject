require('dotenv').config();
const express = require('express');
const fs = require('fs');
const mountRoutes = require('./routes/index');
const https = require('https');
const dbConnection = require('./config/database');
const mountMiddlewares = require('./middlewares/index');
const globalErrorMiddleware = require('./middlewares/errorMiddleware')
// Initialize Express
const app = express();

// Connect to the database
dbConnection();

// Mount middlewares
mountMiddlewares(app);

// Mount routes
mountRoutes(app);

// Handle undefined routes
app.all('*', (req, res, next) => {
  const error = new Error('Route not found');
  error.statusCode = 404;
  error.statusText = 'Not Found';
  next(error);
});

// Global error handling middleware
app.use(globalErrorMiddleware);

// HTTPS server options
const options = {
  key: fs.readFileSync('./cert/key.pem'),
  cert: fs.readFileSync('./cert/cert.pem'),
};

// Start HTTPS server
const server = https.createServer(options, app);
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`HTTPS Server running on port ${PORT}`);
});


// Handle unhandled promise rejections
process.on('unhandledRejection', (error) => {
  console.error('Unhandled Rejection:', error);

  // Gracefully shut down the server
  server.close(() => {
    console.error('Shutting down the server due to an unhandled rejection.');
    process.exit(1); // Exit process after the server has closed
  });

  // Force exit after a timeout to prevent hanging in rare cases
  setTimeout(() => {
    console.error('Forcefully shutting down the process.');
    process.exit(1);
  }, 10000).unref(); // Ensure the timeout doesn't prevent process exit
});

// Optional: Handle uncaught exceptions (unexpected synchronous errors)
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);

  // Gracefully shut down the server
  server.close(() => {
    console.error('Shutting down the server due to an uncaught exception.');
    process.exit(1);
  });

  // Force exit after a timeout
  setTimeout(() => {
    console.error('Forcefully shutting down the process.');
    process.exit(1);
  }, 10000).unref();
});
