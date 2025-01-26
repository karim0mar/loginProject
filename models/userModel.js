const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const User = new mongoose.Schema(
    {
        username: {
            type: String,
            required: [true, 'Username is required'],
            unique: true,
            trim: true
        },
        password: {
            type: String,
            select :false,
            required: [true, 'Password is required'],
            minLength: [6, 'Password must be at least 6 characters'],
        },
        role : {
            type: String,
            enum: ['user', 'admin'],
            default: 'user'
        },
        active: {
            type: Boolean,
            default: true
        },
        refreshToken: {
            type: String,
            select: false
        },
userAgent:{
            type:String,
    default: null,
},deviceId :{
            type:String,
            default: null,
},
    },{timeStamps: true}

);
User.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  // Hashing user password
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
module.exports =mongoose.model('User' , User);