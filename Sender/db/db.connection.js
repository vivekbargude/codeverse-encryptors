const mongoose = require('mongoose');
const colors = require('colors');
const DB_URL = "mongodb://localhost:27017/SenderSwitch"

const connection = mongoose
.connect(DB_URL)
.then(()=>{
    console.log("Database Connected.".yellow.bold);
}).catch((e)=>{
    console.log("Connection Failed!!".red.bold);
});


module.exports = connection;