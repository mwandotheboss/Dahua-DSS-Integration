const fs = require('fs');
const axios = require('axios'); // For HTTP requests
const mqtt = require('mqtt'); // For subscribing to MQ events
const mysql = require('mysql2/promise'); // MySQL client

// DSS API Configuration
const DSS_API_BASE = 'http://41.139.152.133:80';
// const DSS_API_BASE = 'https://10.1.1.3:443';
const DSS_USERNAME = 'system';
const DSS_PASSWORD = 'Admin@123';
const DSS_CLIENT_TYPE = 'NODE_APP';
let token = '';

// MySQL Configuration
const MYSQL_CONFIG = {
    host: 'localhost',
    user: 'root',
    password: 'admin@123',
    database: 'access_control',
};


// Log file
const LOG_FILE = 'access_logs.log';

// Utility to log both to console and a file
function logMessage(message) {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${message}\n`;

    // Log to console
    console.log(formattedMessage.trim());

    // Write to log file
    try {
        fs.appendFileSync(LOG_FILE, formattedMessage, { flag: 'a' });
    } catch (err) {
        console.error(`[ERROR] Failed to write to log file: ${err.message}`);
    }
}

// Retry mechanism to restart the script in case of failure
async function retryOnFailure(task, delayMs = 5000, maxRetries = Infinity) {
    let attempts = 0;
    while (attempts < maxRetries) {
        try {
            await task();
            break; // If the task succeeds, exit the loop
        } catch (error) {
            attempts++;
            logMessage(`Error occurred (attempt ${attempts}): ${error.message}. Retrying in ${delayMs / 1000}s...`);
            await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
    }
}

// Authenticate and Get Token
async function authenticate() {
    try {
        // First login to get encryption parameters
        const firstLogin = await axios.post(`${DSS_API_BASE}/api/v1.0/accounts/authorize`, {
            userName: DSS_USERNAME,
            clientType: DSS_CLIENT_TYPE
        });

        const { realm, randomKey } = firstLogin.data;
        const signature = generateSignature(DSS_USERNAME, DSS_PASSWORD, realm, randomKey);

        // Second login to get the token
        const secondLogin = await axios.post(`${DSS_API_BASE}/api/v1.0/accounts/authorize`, {
            signature,
            userName: DSS_USERNAME,
            randomKey,
            clientType: DSS_CLIENT_TYPE
        });

        token = secondLogin.data.token;
        logMessage('Token obtained: ' + token);
    } catch (error) {
        logMessage('Authentication failed: ' + (error.response?.data || error.message));
        throw error;
    }
}

// Subscribe to Access Control Events
async function subscribeToEvents() {
    try {
        // Get MQ Configuration
        const mqConfig = await axios.get(`${DSS_API_BASE}/api/v1.0/basic-data/mq-config`, {
            headers: { 'X-Subject-Token': token }
        });

        const { ip, port, userName, password, topic } = mqConfig.data;

        // Connect to MQ
        const client = mqtt.connect(`mqtt://${ip}:${port}`, {
            username: userName,
            password: decryptPassword(password), // Decrypt MQ password if needed
        });

        client.on('connect', () => {
            logMessage('Connected to MQ');
            client.subscribe(topic, (err) => {
                if (err) logMessage('Subscription failed: ' + err.message);
                else logMessage('Subscribed to topic: ' + topic);
            });
        });

        client.on('message', async (topic, message) => {
            logMessage('Event received: ' + message.toString());
            const eventData = JSON.parse(message.toString());
            if (eventData.type === 'ACCESS_CONTROL_SWIPE') {
                await handleAccessControlSwipe(eventData);
            }
        });

        client.on('error', (error) => {
            logMessage(`MQTT client error: ${error.message}`);
            client.end(); // Disconnect the client
            throw error;
        });

    } catch (error) {
        logMessage('Event subscription failed: ' + error.message);
        throw error;
    }
}

// Handle Access Control Swipe Events
async function handleAccessControlSwipe(eventData) {
    const connection = await mysql.createConnection(MYSQL_CONFIG);
    try {
        const { userId, cardNumber, accessPoint, time } = eventData.info; // Adjust based on actual event structure
        const query = `
            INSERT INTO access_logs (user_id, card_number, access_point, access_time)
            VALUES (?, ?, ?, ?)
        `;
        await connection.execute(query, [userId, cardNumber, accessPoint, new Date(time)]);
        logMessage('Swipe event logged: ' + JSON.stringify({ userId, cardNumber, accessPoint, time }));
    } catch (error) {
        logMessage('Failed to log swipe event: ' + error.message);
    } finally {
        await connection.end();
    }
}

// Helper Functions
function generateSignature(userName, password, realm, randomKey) {
    const crypto = require('crypto');
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    const temp = crypto.createHash('md5').update(userName + hashedPassword).digest('hex');
    const final = crypto.createHash('md5').update(`${userName}:${realm}:${temp}`).digest('hex');
    return crypto.createHash('md5').update(`${final}:${randomKey}`).digest('hex');
}

function decryptPassword(encryptedPassword) {
    // Example for AES decryption. Modify based on your encryption logic.
    const crypto = require('crypto');
    const decipher = crypto.createDecipheriv('aes-128-cbc', '<AES_KEY>', '<AES_IV>');
    let decrypted = decipher.update(encryptedPassword, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Main Function
async function main() {
    logMessage('Script started.');
    await retryOnFailure(async () => {
        await authenticate();
        await subscribeToEvents();
    });
}

// Run the Script
main().catch((err) => {
    logMessage('Script terminated with error: ' + err.message);
});
