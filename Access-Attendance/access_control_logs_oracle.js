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
    poolMin: 5,            // Increased for higher load
    poolMax: 50,           // Increased for concurrent operations
    poolIncrement: 5,      // Faster pool scaling
    poolTimeout: 300,
    stmtCacheSize: 100,    // Increased for better query caching
    queueTimeout: 60000,
    enableStatistics: true,
    prefetchRows: 1000     // Optimize prefetching for large result sets
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

        // Add indexes for better query performance
        try {
            await connection.execute(`
                BEGIN
                    EXECUTE IMMEDIATE 'CREATE INDEX idx_access_logs_alarm_time ON access_logs(alarm_time)';
                    EXECUTE IMMEDIATE 'CREATE INDEX idx_access_logs_person_id ON access_logs(person_id)';
                EXCEPTION
                    WHEN OTHERS THEN
                        IF SQLCODE = -955 THEN NULL; -- Index already exists
                        ELSE RAISE;
                        END IF;
                END;
            `);
        } catch (error) {
            logMessage('Warning: Index creation failed: ' + error.message);
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

// Add batch size configuration
const BATCH_CONFIG = {
    fetchSize: 1000,        // Fetch 1000 records at a time from DSS
    insertBatchSize: 500,   // Insert 500 records at a time to Oracle
    maxRetries: 3
};

// Modify fetchAccessLogs to handle pagination
async function fetchAccessLogs() {
    try {
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const startTime = currentTimestamp - (24 * 60 * 60);
        let page = 1;
        let hasMoreRecords = true;
        let totalProcessed = 0;

        while (hasMoreRecords) {
            const payload = {
                page: page.toString(),
                pageSize: BATCH_CONFIG.fetchSize.toString(),
                startTime: startTime.toString(),
                endTime: currentTimestamp.toString(),
            };

            const response = await axios.post(
                `${DSS_API_BASE}/obms/api/v1.1/acs/access/record/fetch/page`, 
                payload,
                {
                    headers: {
                        'Accept-Language': 'en',
                        'X-Subject-Token': token,
                        'Content-Type': 'application/json;charset=UTF-8',
                    },
                    httpsAgent: agent,
                }
            );

            if (response.data?.data?.pageData) {
                const records = response.data.data.pageData;
                if (records.length > 0) {
                    // Process records in smaller batches
                    for (let i = 0; i < records.length; i += BATCH_CONFIG.insertBatchSize) {
                        const batch = records.slice(i, i + BATCH_CONFIG.insertBatchSize);
                        await compareWithDB(batch);
                        totalProcessed += batch.length;
                    }
                    page++;
                } else {
                    hasMoreRecords = false;
                }
            } else {
                hasMoreRecords = false;
            }

            logMessage(`Processed ${totalProcessed} records so far`);
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

// Add retry logic for database operations
async function executeWithRetry(operation, maxRetries = 3) {
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;
            if (error.errorNum === 12514) { // TNS:listener could not resolve service
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
                continue;
            }
            throw error; // Throw immediately for other errors
        }
    }
    throw lastError;
}

// Modify compareWithDB to handle record checking differently
async function compareWithDB(logs) {
    return executeWithRetry(async () => {
        let connection;
        try {
            connection = await pool.getConnection();
            
            // Process in chunks to avoid memory issues
            const chunkSize = 1000;
            for (let i = 0; i < logs.length; i += chunkSize) {
                const logsChunk = logs.slice(i, i + chunkSize);
                
                // Create a string of bind variables
                const bindPlaceholders = logsChunk.map((_, index) => `:${index + 1}`).join(',');
                const recordsToCheck = logsChunk.map(log => log.id);

                const result = await connection.execute(
                    `SELECT record_id FROM access_logs 
                     WHERE record_id IN (${bindPlaceholders})`,
                    recordsToCheck,
                    { autoCommit: true }
                );

                const existingRecords = new Set(result.rows.map(row => row[0]));

                // Prepare batch insert for new records
                const newRecords = logsChunk.filter(log => !existingRecords.has(log.id));
                
                if (newRecords.length > 0) {
                    // Insert records one by one or in smaller batches
                    const insertBinds = newRecords.map(log => ({
                        record_id: log.id,
                        alarm_time: new Date(log.alarmTime * 1000),
                        device_code: log.deviceCode,
                        device_name: log.deviceName,
                        channel_id: log.channelId,
                        channel_name: log.channelName,
                        alarm_type_id: log.alarmTypeId,
                        alarm_type_name: log.alarmTypeName,
                        person_id: log.personId,
                        first_name: log.firstName,
                        last_name: log.lastName,
                        capture_image_url: log.captureImageUrl,
                        point_name: log.pointName
                    }));

                    const insertSql = `
                        INSERT INTO access_logs (
                            record_id, alarm_time, device_code, device_name, 
                            channel_id, channel_name, alarm_type_id, alarm_type_name,
                            person_id, first_name, last_name, capture_image_url, point_name
                        ) VALUES (
                            :record_id, :alarm_time, :device_code, :device_name,
                            :channel_id, :channel_name, :alarm_type_id, :alarm_type_name,
                            :person_id, :first_name, :last_name, :capture_image_url, :point_name
                        )`;

                    const options = {
                        autoCommit: true,
                        bindDefs: {
                            record_id: { type: oracledb.STRING, maxSize: 100 },
                            alarm_time: { type: oracledb.DATE },
                            device_code: { type: oracledb.STRING, maxSize: 100 },
                            device_name: { type: oracledb.STRING, maxSize: 200 },
                            channel_id: { type: oracledb.STRING, maxSize: 100 },
                            channel_name: { type: oracledb.STRING, maxSize: 200 },
                            alarm_type_id: { type: oracledb.STRING, maxSize: 100 },
                            alarm_type_name: { type: oracledb.STRING, maxSize: 200 },
                            person_id: { type: oracledb.STRING, maxSize: 100 },
                            first_name: { type: oracledb.STRING, maxSize: 200 },
                            last_name: { type: oracledb.STRING, maxSize: 200 },
                            capture_image_url: { type: oracledb.STRING, maxSize: 500 },
                            point_name: { type: oracledb.STRING, maxSize: 200 }
                        }
                    };

                    await connection.executeMany(insertSql, insertBinds, options);
                    logMessage(`Batch inserted ${newRecords.length} new records`);
                }
            }
        } finally {
            if (connection) {
                try {
                    await connection.close();
                } catch (error) {
                    logMessage('Error closing connection: ' + error.message);
                }
            }
        }
    });
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
