const mongoose = require('mongoose');

const AdminSchema = mongoose.Schema({

    username : {
        required : true,
        type : String,
    },

    password : {
        type : String,
        required : true,

    }

});

const AdminModel = mongoose.model('Admin',AdminSchema);

module.exports = AdminModel;