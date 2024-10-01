// decryption_server.js

const express = require('express');
const bodyParser = require('body-parser');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const db = require('./db/db.connection');
const AdminModel = require('./db/admin.model');

const app = express();
app.use(bodyParser.json());

// Function to decrypt RSA encrypted data
function decryptDataRSA(privateKey, encryptedData) {
    const key = new NodeRSA(privateKey);
    return key.decrypt(encryptedData, 'utf8');
}

// Function to decrypt AES encrypted data
function decryptDataAES(key, iv, encryptedData) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Function to decrypt DES encrypted data
function decryptDataDES(key, iv, encryptedData) {
    const decipher = crypto.createDecipheriv('des-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

app.post('/create-admin',async(req,res)=>{

    try{

        const { username , password } = req.body;

        let admin = new AdminModel({
            username ,
            password
        });

        admin = await admin.save();

        res.status(200).json({
            success : true,
            msg : "User created succcessfully.",
            data : admin
        });



    }catch(e){
        res.send(500).json({
            "success":false,
            "message":e.message
        })
    }

});

app.post('/admin-login',async(req,res)=>{

    try {

        const {username,password} = req.body;

        const admin = await AdminModel.findOne({username});

        if(!admin){
            return res.status(404).json({
                "success":false,
                "message":"Admin not found"
            });
        }

        if(admin.password===password){
            return res.status(200).json({
                "success":true,
                "message":"Admin logged in successfully",
            });
        }else

        {
            return res.status(404).json({
            "success":false,
            "message":"Invalid password"
        });
        }
    } catch (error) {
        res.status(500).json({
            "success":false,
            "message":error.message
        })
    }

});


// Main decryption logic based on the algorithm used
app.post('/decrypt', (req, res) => {
    const { encryptedData, encryptionDetails, algorithm } = req.body;

    let decryptedData;

    if (algorithm === 'rsa') {
        // RSA decryption
        decryptedData = decryptDataRSA(encryptionDetails.privateKey, encryptedData);

    } else if (algorithm === 'aes') {
        // AES decryption
        decryptedData = decryptDataAES(encryptionDetails.key, encryptionDetails.iv, encryptedData);

    } else if (algorithm === 'des') {
        // DES decryption
        decryptedData = decryptDataDES(encryptionDetails.key, encryptionDetails.iv, encryptedData);

    } else {
        return res.status(400).json({ error: 'Unsupported decryption algorithm.' });
    }

    console.log(`Decrypted data using ${algorithm}: ${decryptedData}`);

    // Send decrypted data back to the receiver or next step in the process
    res.json({ decrypted_data: decryptedData });
});

app.listen(5002, () => {
    console.log('Decryption Server is running on port 5002...');
});
