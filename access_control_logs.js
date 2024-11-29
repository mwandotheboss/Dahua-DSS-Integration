const axios = require('axios');
const crypto = require('crypto-js/md5');
const https = require('https');
const mysql = require('mysql2/promise');

// DSS API Configuration
const DSS_API_BASE = 'https://41.139.152.133:443'; // Base URL without /brms
const DSS_USERNAME = 'system';
const DSS_PASSWORD = 'Admin@123'; 
const DSS_CLIENT_TYPE = 'NODE_APP';
let token = '';
let subjectToken = '';

// MySQL Configuration
const MYSQL_POOL_CONFIG = {
    host: 'localhost',
    user: 'root',
    password: 'Admin@123',
    database: 'access_control',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Utility to log messages to the console
function logMessage(message) {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${message}\n`;
    console.log(formattedMessage.trim());
}

// Create an https agent that allows self-signed certificates
const agent = new https.Agent({
    rejectUnauthorized: false 
});

// MD5 encryption method
function md5(val) {
    return crypto(val).toString();  // Using crypto-js MD5
}

// Authenticate and retrieve token
async function authenticate() {
    try {
        // Step 1: First login to get realm and randomKey
        const firstLogin = await axios.post(`${DSS_API_BASE}/brms/api/v1.0/accounts/authorize`, {
            userName: DSS_USERNAME,
            clientType: DSS_CLIENT_TYPE,
        }, {
            httpsAgent: agent,  // Use the custom https agent
            maxRedirects: 5,  // Allow redirects
            validateStatus: (status) => status === 200 || status === 301 || status === 401,  // Allow 200, 301, 401 status codes
            headers: {
                'Accept-Language': 'en',
                'Content-Type': 'application/json;charset=UTF-8',
                'User-Agent': 'Node.js App',
                'Referer': `${DSS_API_BASE}/brms`,
                'Time-Zone': 'Africa/Nairobi',
            }
        });

        logMessage('First login successful: realm = ' + firstLogin.data.realm + ', randomKey = ' + firstLogin.data.randomKey);
        
        if (firstLogin.data.realm && firstLogin.data.randomKey && firstLogin.data.publickey) {
            realm = firstLogin.data.realm;
            randomKey = firstLogin.data.randomKey;
            publicKey = firstLogin.data.publickey;

            logMessage('First login raw response: ' + JSON.stringify(firstLogin.data));
        } else {
            throw new Error('First login response does not contain valid realm, randomKey, or public key.');
        }

        // Step 2: Generate signature (hashing and combining)
        const temp1 = md5(DSS_PASSWORD); 
        logMessage(`MD5 of password: ${temp1}`);

        const temp2 = md5(DSS_USERNAME + temp1); 
        logMessage(`Double hash (username + hashed password): ${temp2}`);

        const temp3 = md5(temp2); 
        logMessage(`MD5 of second hash: ${temp3}`);

        const temp4 = md5(DSS_USERNAME + ":" + realm + ":" + temp3); 
        logMessage(`Concatenation of username, realm, and temp3: ${temp4}`);

        const signatureString = `${temp4}:${randomKey}`; 
        const finalSignature = md5(signatureString); 
        logMessage(`Final signature with randomKey: ${finalSignature}`);

        const requestData = {
            signature: finalSignature,
            userName: DSS_USERNAME,
            randomKey,
            clientType: DSS_CLIENT_TYPE,
        };

        logMessage('Second login request payload: ' + JSON.stringify(requestData));

        const secondLogin = await axios.post(`${DSS_API_BASE}/brms/api/v1.0/accounts/authorize`, requestData, {
            httpsAgent: agent,
            headers: {
                'Accept-Language': 'en',
                'Content-Type': 'application/json;charset=UTF-8',
                'User-Agent': 'Node.js App',
                'Referer': `${DSS_API_BASE}/brms`,
                'Time-Zone': 'Africa/Nairobi',
            }
        });

        logMessage('Second login response: ' + JSON.stringify(secondLogin.data));

        token = secondLogin.data.token;
        subjectToken = secondLogin.data.credential;

        if (!token) {
            logMessage('Token is undefined in second login response.');
            throw new Error('Token is undefined. Check credentials and server configuration.');
        }

        logMessage(`Token obtained successfully: ${token}`);

    } catch (error) {
        logMessage('Authentication failed: ' + error.message);
        throw error;
    }
}

// Fetch and process access logs every minute
async function fetchAccessLogs() {
    try {
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const startTime = currentTimestamp - 60;
        const endTime = currentTimestamp;

        const payload = {
            page: "1",
            pageSize: "20",
            startTime: startTime.toString(),
            endTime: endTime.toString(),
            channelIds: [],
            alarmTypeIds: [],
            personId: "",
        };

        const response = await axios.post(`${DSS_API_BASE}/obms/api/v1.1/acs/access/record/fetch/page`, payload, {
            headers: {
                'Accept-Language': 'en',
                'X-Subject-Token': subjectToken,
                'Content-Type': 'application/json;charset=UTF-8',
            },
            httpsAgent: agent,
        });

        logMessage('Fetched access logs successfully.');

        // Insert data into database
        await insertSwipeRecordToDB(response.data);
    } catch (error) {
        logMessage('Error fetching access logs: ' + error.message);
    }
}

// Insert swipe record data into the MySQL database
async function insertSwipeRecordToDB(record) {
    const connection = await mysql.createPool(MYSQL_POOL_CONFIG);
    try {
        const records = record.data.pageData;
        for (const recordData of records) {
            const { 
                id, alarmTime, deviceCode, deviceName, channelId, channelName,
                alarmTypeId, personId, firstName, lastName, captureImageUrl
            } = recordData;

            const query = `
                INSERT INTO access_logs 
                (record_id, alarm_time, device_code, device_name, channel_id, 
                channel_name, alarm_type_id, person_id, first_name, last_name, capture_image_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            await connection.execute(query, [
                id, new Date(alarmTime * 1000), deviceCode, deviceName, channelId, 
                channelName, alarmTypeId, personId, firstName, lastName, captureImageUrl
            ]);
        }

        logMessage('Swipe event logged into MySQL database.');
    } catch (error) {
        logMessage('Failed to log swipe event: ' + error.message);
    } finally {
        await connection.end();
    }
}

// Main function
async function main() {
    logMessage('Script started.');
    try {
        await authenticate();  // Perform first login, second login to get the token
        setInterval(fetchAccessLogs, 60000);  // Fetch access logs every minute
    } catch (error) {
        logMessage('Script terminated with error: ' + error.message);
    }
}

main();
