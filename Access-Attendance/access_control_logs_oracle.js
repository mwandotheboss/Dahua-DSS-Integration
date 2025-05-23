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
    poolMin: 2,                // Reduced minimum connections
    poolMax: 20,               // Reduced maximum connections
    poolIncrement: 2,          // Smaller increment
    poolTimeout: 300,
    stmtCacheSize: 50,         // Reduced cache size
    queueTimeout: 60000,
    enableStatistics: true,
    prefetchRows: 500          // Reduced prefetch size
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

// Add memory and performance configurations
const PERFORMANCE_CONFIG = {
    memory: {
        maxHeapUsage: 512 * 1024 * 1024,  // Reduced to 512MB max heap (safe for 16GB system)
        gcThreshold: 0.7                   // Trigger GC earlier at 70% usage
    },
    batch: {
        recentBatchSize: 50,              // Smaller batches for recent records
        historyBatchSize: 200,            // Reduced historical batch size
        maxRetries: 3,
        queryTimeout: 45000               // Increased to 45 seconds for slower network
    },
    timeWindows: {
        recent: 2 * 60 * 60,              // 2 hours in seconds (unchanged)
        history: 24 * 60 * 60             // 24 hours in seconds (unchanged)
    },
    intervals: {
        recentRecords: 120000,            // Check recent records every 2 minutes
        historicalRecords: 600000,        // Check historical records every 10 minutes
        delayBetweenChunks: 200          // 200ms delay between chunks
    }
};

// Add memory monitoring
function checkMemoryUsage() {
    const used = process.memoryUsage();
    const heapUsed = used.heapUsed;
    const heapTotal = used.heapTotal;
    const usage = heapUsed / PERFORMANCE_CONFIG.memory.maxHeapUsage;

    logMessage(`Memory Usage: ${Math.round(heapUsed / 1024 / 1024)}MB / ${Math.round(heapTotal / 1024 / 1024)}MB`);

    if (usage > PERFORMANCE_CONFIG.memory.gcThreshold) {
        if (global.gc) {
            global.gc();
            logMessage('Garbage collection triggered');
        }
        return true; // Memory pressure detected
    }
    return false;
}

// Split fetchAccessLogs into two functions - one for recent and one for historical records
async function fetchRecentAccessLogs() {
    try {
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const startTime = currentTimestamp - PERFORMANCE_CONFIG.timeWindows.recent;
        
        await fetchLogsInTimeWindow(
            startTime, 
            currentTimestamp, 
            PERFORMANCE_CONFIG.batch.recentBatchSize,
            'recent'
        );
    } catch (error) {
        logMessage('Error fetching recent access logs: ' + error.message);
        handleFetchError(error);
    }
}

async function fetchHistoricalAccessLogs() {
    try {
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const startTime = currentTimestamp - PERFORMANCE_CONFIG.timeWindows.history;
        const recentStartTime = currentTimestamp - PERFORMANCE_CONFIG.timeWindows.recent;
        
        await fetchLogsInTimeWindow(
            startTime, 
            recentStartTime, 
            PERFORMANCE_CONFIG.batch.historyBatchSize,
            'historical'
        );
    } catch (error) {
        logMessage('Error fetching historical access logs: ' + error.message);
        handleFetchError(error);
    }
}

async function fetchLogsInTimeWindow(startTime, endTime, batchSize, type) {
    let page = 1;
    let hasMoreRecords = true;
    let totalProcessed = 0;
    let memoryPressure = false;

    while (hasMoreRecords && !memoryPressure) {
        const payload = {
            page: page.toString(),
            pageSize: batchSize.toString(),
            startTime: startTime.toString(),
            endTime: endTime.toString(),
        };

        try {
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
                    timeout: PERFORMANCE_CONFIG.batch.queryTimeout
                }
            );

            if (response.data?.data?.pageData) {
                const records = response.data.data.pageData;
                if (records.length > 0) {
                    // Process records with memory checks
                    memoryPressure = await processRecordsBatch(records, type);
                    totalProcessed += records.length;
                    page++;
                } else {
                    hasMoreRecords = false;
                }
            } else {
                hasMoreRecords = false;
            }

            logMessage(`${type} records processed: ${totalProcessed}`);
        } catch (error) {
            handleFetchError(error);
            break;
        }
    }
}

async function processRecordsBatch(records, type) {
    const batchStartTime = Date.now();
    let processed = 0;

    try {
        const chunkSize = type === 'recent' ? 25 : 50; // Smaller chunks
        for (let i = 0; i < records.length; i += chunkSize) {
            // Check both memory and CPU
            const memoryPressure = checkMemoryUsage();
            const highCPULoad = checkSystemLoad();

            if (memoryPressure || highCPULoad) {
                logMessage(`Resource pressure detected: Memory=${memoryPressure}, CPU=${highCPULoad}`);
                // Add longer delay if system is under pressure
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }

            const chunk = records.slice(i, i + chunkSize);
            await compareWithDB(chunk);
            processed += chunk.length;

            // Always add delay between chunks
            await new Promise(resolve => 
                setTimeout(resolve, PERFORMANCE_CONFIG.intervals.delayBetweenChunks)
            );
        }
    } catch (error) {
        logMessage(`Error processing ${type} batch: ${error.message}`);
        throw error;
    }

    const duration = Date.now() - batchStartTime;
    logMessage(`${type} batch processed ${processed} records in ${duration}ms`);
    return false;
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

// Add CPU monitoring
function checkSystemLoad() {
    const cpus = require('os').cpus();
    const totalLoad = cpus.reduce((acc, cpu) => acc + (cpu.times.user + cpu.times.system), 0);
    const totalIdle = cpus.reduce((acc, cpu) => acc + cpu.times.idle, 0);
    const cpuUsage = (totalLoad / (totalLoad + totalIdle)) * 100;
    
    logMessage(`CPU Usage: ${Math.round(cpuUsage)}%`);
    return cpuUsage > 80; // Return true if CPU usage is too high
}

// Modify init function to handle both recent and historical fetches
async function init() {
    try {
        // Log initial system state
        logMessage('System Information:');
        logMessage(`Total Memory: ${Math.round(require('os').totalmem() / 1024 / 1024)}MB`);
        logMessage(`CPUs: ${require('os').cpus().length}`);
        
        await initializePool();
        await authenticate();

        // Start monitoring intervals with staggered starts
        setTimeout(() => {
            setInterval(fetchRecentAccessLogs, PERFORMANCE_CONFIG.intervals.recentRecords);
        }, 1000);

        setTimeout(() => {
            setInterval(fetchHistoricalAccessLogs, PERFORMANCE_CONFIG.intervals.historicalRecords);
        }, 5000);

        // Initial fetch after short delay
        setTimeout(fetchRecentAccessLogs, 2000);
    } catch (error) {
        logMessage('Initialization failed: ' + error.message);
        await cleanup();
    }
}

// Add error handling utility
function handleFetchError(error) {
    if (error.response) {
        if (error.response.status === 401) {
            logMessage('Authentication failed, re-authenticating...');
            authenticate().catch(authError => {
                logMessage('Re-authentication failed: ' + authError.message);
            });
        } else {
            logMessage('Response error: ' + JSON.stringify(error.response.data));
            logMessage('Error status code: ' + error.response.status);
        }
    } else {
        logMessage('Request error: ' + error.message);
    }
}

init();
