// controllers/authController.js
const User = require('../models/userModel');
const AppError = require('../utils/AppError');
const asyncHandler = require('express-async-handler');
const verifySignature = require('../utils/verifySignature');
const { generateToken } = require('../utils/jwtUtils');
const validateUser = require('../utils/userValidation');
const jwt = require('jsonwebtoken');
const {body} = require("express-validator"); // Ensure JWT is imported

// Login Controller
const login = asyncHandler(async (req, res, next) => {
  const { username, password } = req.body;
  const signature = req.headers['signature'];
  const timestamp = req.headers['timestamp'];
  const deviceId = req.headers['device-id'];
  const userAgent = req.headers['user-agent'];

  const token2 = generateToken("testing", process.env.JWT_SECRET_KEY, process.env.JWT_EXPIRE_TIME);
  console.log(token2);
  if (!timestamp) {
    return next(new AppError('Missing timestamp in request', 403, 'Forbidden'));
  }

  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - timestamp) > 5 * 60) {
    return next(new AppError('Request timestamp is invalid or expired', 403, 'Forbidden'));
  }

  const data = `username=${username}&password=${password}&timestamp=${timestamp}`;
  if (!verifySignature(data, signature, process.env.API_KEY)) {
    return next(new AppError('Invalid signature', 403, 'Forbidden'));
  }

  const user = await validateUser(username, password);
  if (!user) {
    return next(new AppError('Incorrect username or password', 401, 'Unauthorized'));
  }

  if (!user.active) {
    return next(new AppError('The account is disabled', 401, 'Unauthorized'));
  }

  const token = generateToken(user._id, process.env.JWT_SECRET_KEY, process.env.JWT_EXPIRE_TIME);
  const refreshToken = generateToken(user._id, process.env.JWT_REFRESH_SECRET_KEY, process.env.JWT_REFRESH_EXPIRE_TIME);

  const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
  user.refreshToken = hashedRefreshToken;
  user.deviceId = deviceId; // Store deviceId
  user.userAgent = userAgent; // Store userAgent
  user.refreshToken = refreshToken;
  await user.save();

  res.status(200).json({
    data: { username: user.username, role: user.role, active: user.active },
    token,
    refreshToken,
  });
});

// Protect Middleware
const protect = asyncHandler(async (req, res, next) => {
  let token;
  let refreshToken;
  const deviceId = req.headers['device-id'];
  const userAgent = req.headers['user-agent'];
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (req.body.refreshToken) {
    refreshToken = req.body.refreshToken;
  }

  if (!token) {
    return next(new AppError('You are not logged in. Please log in to access this route.', 401, 'Unauthorized'));
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
  } catch (err) {
    if (err.name === 'TokenExpiredError' && refreshToken) {
      try {
        const decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET_KEY);
        const user = await User.findOne({ _id: decodedRefresh.UserId, refreshToken });
        if (!user) {
          return next(new AppError('Invalid Refresh Token', 403, 'Forbidden'));
        }

        const newToken = generateToken(user._id, process.env.JWT_SECRET_KEY, process.env.JWT_EXPIRE_TIME);
        res.status(200).json({ token: newToken });
        return;
      } catch (refreshErr) {
        return next(new AppError('Invalid or expired Refresh Token', 403, 'Forbidden'));
      }
    }
    return next( new AppError('Invalid or expired token', 401, 'Unauthorized'));
  }

  const currentUser = await User.findById(decoded.UserId);
  if (!currentUser) {
    return next( new AppError('The user belonging to this token no longer exists', 401, 'Unauthorized'));
  }

  // Check deviceId and userAgent
  if (currentUser.deviceId !== deviceId || currentUser.userAgent !== userAgent) {
    logSuspiciousRequest(req, 'DeviceId or UserAgent mismatch');
    return next(new AppError('Device or session mismatch', 403, 'Forbidden'));
  }
  const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);
  if (!isMatch) {
    return next(new AppError('Invalid Refresh Token', 403, 'Forbidden'));
  }
  req.user = currentUser;
  next();
});

// Refresh Controller
const refresh = asyncHandler(async (req, res, next) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return next(new AppError('Refresh Token is required', 400, 'Bad Request'));
  }
  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET_KEY);
  } catch (err) {
    return next(new AppError('Invalid or expired Refresh Token', 403, 'Forbidden'));
  }

  const user = await User.findOne({ _id: decoded.UserId, refreshToken });
  if (!user) {
    return next(new AppError('Invalid Refresh Token', 403, 'Forbidden'));
  }

  const newToken = generateToken(user._id, process.env.JWT_SECRET_KEY, process.env.JWT_EXPIRE_TIME);
  res.status(200).json({ token: newToken });
});

module.exports = { login, protect, refresh };
