// encryption_server.js

const express = require('express');
const bodyParser = require('body-parser');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const axios = require('axios');
const db = require("./db/db.connection");
const AdminModel = require('./db/admin.model');
const vault = require('node-vault')({ apiVersion :'v1',endpoint: 'http://127.0.0.1:8200',token: 'hvs.bDG0sobTSY418sFM6r2I4GRI' });

const app = express();
app.use(bodyParser.json());

// Function to generate RSA keys dynamically
function generateRSAKeyPair() {
    const key = new NodeRSA({ b: 2048 });
    return {
        publicKey: key.exportKey('public'),
        privateKey: key.exportKey('private')
    };
}

// Function to encrypt data using RSA public key
function encryptDataRSA(publicKey, data) {
    const key = new NodeRSA(publicKey);
    return key.encrypt(data, 'base64');
}

// Function to generate a random AES key
function generateAESKey() {
    return crypto.randomBytes(32); // 256-bit AES key
}

// Function to encrypt data using AES algorithm
function encryptDataAES(key, data) {
    const iv = crypto.randomBytes(16); // Generate random initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return { encryptedData: encrypted, key: key.toString('base64'), iv: iv.toString('base64') };
}

// Function to generate a random DES key
function generateDESKey() {
    return crypto.randomBytes(8); // 64-bit DES key
}

// Function to encrypt data using DES algorithm
function encryptDataDES(key, data) {
    const iv = crypto.randomBytes(8); // DES IV is 8 bytes
    const cipher = crypto.createCipheriv('des-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return { encryptedData: encrypted, key: key.toString('base64'), iv: iv.toString('base64') };
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

async function storeSecret(secretName, secretValue) {
    try {
        await vault.write(`secret/data/${secretName}`,{data:{value:secretValue}});
        console.log(`Secret ${secretName} stored in Vault`);
    } catch (error) {
        console.error('Error storing secret:', error);
    }
}



// Main encryption logic based on the requested algorithm
app.post('/encrypt', async(req, res) => {
    const rawData = req.body.data;
    const requestedAlgorithm = req.body.algorithm || 'rsa'; // Default to RSA if no algorithm is specified

    let encryptedData;
    let encryptionDetails = {}; // Object to store algorithm-specific details (key, iv, etc.)

    if (requestedAlgorithm === 'rsa') {
        // RSA encryption
        const { publicKey, privateKey } = generateRSAKeyPair();
        encryptedData = encryptDataRSA(publicKey, rawData);

//         vault.unseal({ key: '+TqKLbT/LEi49nKLppAJsokge988/BoTJUfFlMsfM1w=' })
//     .then(() => {
//         vault.write('secret/hello', { value: 'world' })
//             .then((res) => console.log(res))
//             .catch((err) => console.error(err));
//     });

// vault.write('secret/hello', { value: 'world', lease: '1s' })
//     .then( () => vault.read('secret/hello'))
//     .then( () => vault.delete('secret/hello'))
//     .catch(console.error)


        console.log(privateKey);
        storeSecret("privateKey",privateKey);
        encryptionDetails = { privateKey };

    } else if (requestedAlgorithm === 'aes') {
        // AES encryption
        const key = generateAESKey();
        const aesEncryption = encryptDataAES(key, rawData);
        encryptedData = aesEncryption.encryptedData;
        encryptionDetails = { key: aesEncryption.key, iv: aesEncryption.iv };

    } else if (requestedAlgorithm === 'des') {
        // DES encryption
        const key = generateDESKey();
        const desEncryption = encryptDataDES(key, rawData);
        encryptedData = desEncryption.encryptedData;
        encryptionDetails = { key: desEncryption.key, iv: desEncryption.iv };

    } else {
        return res.status(400).json({ error: 'Unsupported encryption algorithm.' });
    }

    console.log(`Encrypted data using ${requestedAlgorithm}: ${encryptedData}`);

    // Forward the encrypted data and algorithm-specific details (key, iv, private key) to the Decryption Server
    const decryptionServerUrl = 'http://localhost:5002/decrypt';
    axios.post(decryptionServerUrl, {
        encryptedData: encryptedData,
        encryptionDetails: encryptionDetails, // Send encryption details to the decryption server
        algorithm: requestedAlgorithm // Specify the algorithm used
    })
    .then(response => {
        res.json({
            encrypted_data: encryptedData,
            decryption_server_response: response.data
        });
    })
    .catch(error => {
        res.status(500).json({ error: error.message });
    });
});

app.listen(5001, () => {
    console.log('Encryption Server is running on port 5001...'.blue);
});
