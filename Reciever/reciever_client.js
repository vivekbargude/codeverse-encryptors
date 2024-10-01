// receiver_client.js
const axios = require('axios');
const NodeRSA = require('node-rsa');
const WebSocket = require('ws');

// Function to decrypt RSA encrypted data
function decryptDataRSA(encryptedData, privateKey) {
    const key = new NodeRSA();
    key.importKey(privateKey, 'private');
    return key.decrypt(encryptedData, 'utf8');
}

// Function to connect to the WebSocket server and receive data
function startWebSocket() {
    const ws = new WebSocket('ws://localhost:5002');

    ws.on('open', () => {
        console.log('Connected to WebSocket server.');
    });

    ws.on('message', (data) => {
        const { decrypted_data } = JSON.parse(data);
        console.log('Received decrypted data:', decrypted_data);
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });

    ws.on('close', () => {
        console.log('Disconnected from WebSocket server.');
    });
}

// Call this function to start the WebSocket connection
startWebSocket();
