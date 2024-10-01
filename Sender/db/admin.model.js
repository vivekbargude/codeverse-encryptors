const mongoose = require('mongoose');
const { pharmacySchema } = require('./pharmacymodel');

const UserSchema = mongoose.Schema({

    email : {
        required : true,
        trim : true,
        type : String,
    },

    password : {
        type : String,
        required : true,
        // validate : {
        //     validator : (value) => {
                
        //         return value.length > 6;
        //     },
        //     message : 'Please enter a valid password'
        // },

    }

});

const UserModel = mongoose.model('User',UserSchema);

module.exports = UserModel;