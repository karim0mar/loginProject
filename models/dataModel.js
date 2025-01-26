const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Data = new mongoose.Schema({
    secure_text:{
        type:String,
        unique :true,
        required : true,
    }
});
/*Data.pre('save', (req,res,next)=>{
    if (!this.isModified('secure_text')) next();

        this.secure_text = bcrypt.hashSync(this.secure_text,12);
        next();
})*/
module.exports = mongoose.model('Data',Data);