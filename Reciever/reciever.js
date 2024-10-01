// decryption_server.js
const express = require('express');
const bodyParser = require('body-parser');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const db = require('./db/db.connection');
const AdminModel = require('./db/admin.model');
const WebSocket = require('ws');
const vault = require('node-vault')({ apiVersion :'v1', endpoint: 'http://127.0.0.1:8200' ,token: 'hvs.bDG0sobTSY418sFM6r2I4GRI'});

const app = express();
app.use(bodyParser.json());

// WebSocket Server Setup
const wss = new WebSocket.Server({ noServer: true });

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

app.post('/create-admin', async (req, res) => {
    try {
        const { username, password } = req.body;

        let admin = new AdminModel({
            username,
            password
        });

        admin = await admin.save();

        res.status(200).json({
            success: true,
            msg: "User created successfully.",
            data: admin
        });
    } catch (e) {
        res.status(500).json({
            "success": false,
            "message": e.message
        });
    }
});

app.post('/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const admin = await AdminModel.findOne({ username });

        if (!admin) {
            return res.status(404).json({
                "success": false,
                "message": "Admin not found"
            });
        }

        if (admin.password === password) {
            return res.status(200).json({
                "success": true,
                "message": "Admin logged in successfully",
            });
        } else {
            return res.status(404).json({
                "success": false,
                "message": "Invalid password"
            });
        }
    } catch (error) {
        res.status(500).json({
            "success": false,
            "message": error.message
        });
    }
});

async function retrieveSecret(secretName) {
    try {
        const result = await vault.read(`secret/data/${secretName}`);
        return result.data.data.value;
    } catch (error) {
        console.error('Error retrieving secret:', error);
    }
}

// Main decryption logic based on the algorithm used
app.post('/decrypt', async(req, res) => {
    const { encryptedData, encryptionDetails, algorithm } = req.body;

    let decryptedData;

    if (algorithm === 'rsa') {
        // RSA decryption
        const privateKey = await retrieveSecret('privateKey')
        console.log(privateKey);
        
        decryptedData = decryptDataRSA(privateKey, encryptedData);
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

    // Send decrypted data to all connected WebSocket clients
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ decrypted_data: decryptedData }));
        }
    });

    // Send decrypted data back as response (optional)
    res.json({ decrypted_data: decryptedData });
});

// Upgrade HTTP server to support WebSocket
const server = app.listen(5002, () => {
    console.log('Decryption Server is running on port 5002...');
});

server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});
