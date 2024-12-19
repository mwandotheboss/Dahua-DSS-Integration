// Load environment variables from .env file
require('dotenv').config();

const axios = require('axios');
const crypto = require('crypto-js/md5');
const https = require('https');
const oracledb = require('oracledb');

// DSS API Configuration
const DSS_API_BASE = process.env.DSS_API_BASE;  // Use environment variable
const DSS_USERNAME = process.env.DSS_USERNAME;  // Use environment variable
const DSS_PASSWORD = process.env.DSS_PASSWORD;  // Use environment variable
const DSS_CLIENT_TYPE = process.env.DSS_CLIENT_TYPE;  // Use environment variable
let token = '';
let subjectToken = '';
let realm = '';
let randomKey = '';
let publicKey = '';

// Oracle Configuration
const ORACLE_CONFIG = {
    user: process.env.ORACLE_USER,
    password: process.env.ORACLE_PASSWORD,
    connectString: process.env.ORACLE_CONNECT_STRING,
    poolMin: 1,
    poolMax: 10,
    poolIncrement: 1,
    poolTimeout: 60,
    stmtCacheSize: 30
};

// Initialize Oracle connection pool
let pool;
async function initializePool() {
    try {
        // Set autoCommit to true for automatic transaction management
        oracledb.autoCommit = true;
        pool = await oracledb.createPool(ORACLE_CONFIG);
        logMessage('Oracle connection pool initialized successfully');

        // Create table if it doesn't exist
        const connection = await pool.getConnection();
        try {
            await connection.execute(`
                BEGIN
                    EXECUTE IMMEDIATE 'CREATE TABLE access_logs (
                        record_id VARCHAR2(100) PRIMARY KEY,
                        alarm_time TIMESTAMP,
                        device_code VARCHAR2(100),
                        device_name VARCHAR2(200),
                        channel_id VARCHAR2(100),
                        channel_name VARCHAR2(200),
                        alarm_type_id VARCHAR2(100),
                        alarm_type_name VARCHAR2(200),
                        person_id VARCHAR2(100),
                        first_name VARCHAR2(200),
                        last_name VARCHAR2(200),
                        capture_image_url VARCHAR2(500),
                        point_name VARCHAR2(200),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )';
                EXCEPTION
                    WHEN OTHERS THEN
                        IF SQLCODE = -955 THEN NULL; -- Table already exists
                        ELSE RAISE;
                        END IF;
                END;
            `);
            logMessage('Table access_logs verified/created successfully');
        } finally {
            if (connection) {
                await connection.close();
            }
        }
    } catch (error) {
        logMessage('Failed to initialize Oracle pool: ' + error.message);
        throw error;
    }
}

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
                'Time-Zone': process.env.TIME_ZONE,  // Use environment variable
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
                'Time-Zone': process.env.TIME_ZONE,  // Use environment variable
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

// Fetch access logs for the last 24 hours and compare with the database
async function fetchAccessLogs() {
    try {
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const startTime = currentTimestamp - (24 * 60 * 60);  // 24 hours ago
        const endTime = currentTimestamp;  // Current time

        const payload = {
            page: "1",
            pageSize: "100",  // Increase the number of records to fetch
            startTime: startTime.toString(),
            endTime: endTime.toString(),
        };

        const response = await axios.post(`${DSS_API_BASE}/obms/api/v1.1/acs/access/record/fetch/page`, payload, {
            headers: {
                'Accept-Language': 'en',
                'X-Subject-Token': token, 
                'Content-Type': 'application/json;charset=UTF-8',
            },
            httpsAgent: agent,  // Use the custom agent to bypass SSL verification
        });

        // Log the full response for debugging
        logMessage('Response from fetchAccessLogs: ' + JSON.stringify(response.data));

        // Ensure that the structure matches what we expect
        if (response.data && response.data.data && Array.isArray(response.data.data.pageData)) {
            // Only use pageData for processing
            const pageData = response.data.data.pageData;

            if (pageData.length === 0) {
                logMessage("No access logs found in the last 24 hours.");
            } else {
                // Compare with database (add your DB comparison logic here)
                await compareWithDB(pageData);  // Compare with database
                logMessage('Fetched and compared access logs successfully.');
            }
        } else {
            logMessage('Access logs response structure is not as expected. Response: ' + JSON.stringify(response.data));
            throw new Error('Access logs response structure is not as expected.');
        }
    } catch (error) {
        logMessage('Error fetching access logs: ' + error.message);
        if (error.response) {
            // If we get a 401 error, re-authenticate
            if (error.response.status === 401) {
                logMessage('Authentication failed, re-authenticating...');
                await authenticate();  // Re-authenticate and retry the request
                await fetchAccessLogs();  // Retry fetching the access logs after re-authentication
            } else {
                logMessage('Response from error: ' + JSON.stringify(error.response.data));
                logMessage('Error status code: ' + error.response.status);
            }
        }
    }
}

// Compare fetched access logs with the database
async function compareWithDB(logs) {
    let connection;
    try {
        connection = await pool.getConnection();
        
        for (const log of logs) {
            const { id, alarmTime, deviceCode, deviceName, channelId, channelName, 
                   alarmTypeId, alarmTypeName, personId, firstName, lastName, 
                   captureImageUrl, pointName } = log;

            // Check if record exists
            const result = await connection.execute(
                `SELECT 1 FROM access_logs WHERE record_id = :1`,
                [id],
                { outFormat: oracledb.OUT_FORMAT_OBJECT }
            );

            if (result.rows.length === 0) {
                // Insert new record
                await connection.execute(
                    `INSERT INTO access_logs (
                        record_id, alarm_time, device_code, device_name, 
                        channel_id, channel_name, alarm_type_id, alarm_type_name,
                        person_id, first_name, last_name, capture_image_url, point_name
                    ) VALUES (
                        :1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13
                    )`,
                    [
                        id,
                        new Date(alarmTime * 1000),
                        deviceCode,
                        deviceName,
                        channelId,
                        channelName,
                        alarmTypeId,
                        alarmTypeName,
                        personId,
                        firstName,
                        lastName,
                        captureImageUrl,
                        pointName
                    ]
                );
                logMessage(`Inserted new record with ID: ${id}`);
            }
        }
    } catch (error) {
        logMessage('Error comparing with DB: ' + error.message);
        throw error;
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (error) {
                logMessage('Error closing connection: ' + error.message);
            }
        }
    }
}

// Add a cleanup function for graceful shutdown
async function cleanup() {
    try {
        if (pool) {
            await pool.close(10); // Wait up to 10 seconds for connections to close
            logMessage('Oracle connection pool closed successfully');
        }
    } catch (error) {
        logMessage('Error closing Oracle pool: ' + error.message);
    }
    process.exit(0);
}

// Add event listeners for cleanup
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

// Initialize the authentication and start fetching logs
async function init() {
    try {
        await initializePool();  // Initialize Oracle pool
        await authenticate();    // Authenticate with DSS
        setInterval(fetchAccessLogs, 60000);  // Fetch logs every minute
    } catch (error) {
        logMessage('Initialization failed: ' + error.message);
        await cleanup();
    }
}

init();
