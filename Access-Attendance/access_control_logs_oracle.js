// Load environment variables from .env file
require('dotenv').config();

const axios = require('axios');
const crypto = require('crypto-js/md5');
const https = require('https');
const oracledb = require('oracledb');
const winston = require('winston');
require('winston-daily-rotate-file');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const moment = require('moment-timezone');
const { Parser } = require('json2csv');

// DSS API Configuration
const DSS_API_BASE = process.env.DSS_API_BASE;
const DSS_USERNAME = process.env.DSS_USERNAME;
const DSS_PASSWORD = process.env.DSS_PASSWORD;
const DSS_CLIENT_TYPE = process.env.DSS_CLIENT_TYPE;
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
    poolMin: 2,
    poolMax: 20,
    poolIncrement: 2,
    poolTimeout: 300,
    stmtCacheSize: 50,
    queueTimeout: 60000,
    enableStatistics: true,
    prefetchRows: 500
};

// Initialize Oracle connection pool
let pool;
async function initializePool() {
    try {
        oracledb.autoCommit = true;
        pool = await oracledb.createPool(ORACLE_CONFIG);
        logMessage('Oracle connection pool initialized successfully');

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
                        IF SQLCODE = -955 THEN NULL;
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

        // Re-establish connection for index creation
        const indexConnection = await pool.getConnection();
        try {
            await indexConnection.execute(`
                BEGIN
                    EXECUTE IMMEDIATE 'CREATE INDEX idx_access_logs_alarm_time ON access_logs(alarm_time)';
                    EXECUTE IMMEDIATE 'CREATE INDEX idx_access_logs_person_id ON access_logs(person_id)';
                EXCEPTION
                    WHEN OTHERS THEN
                        IF SQLCODE = -955 THEN NULL;
                        ELSE RAISE;
                        END IF;
                END;
            `);
            logMessage('Indexes created successfully');
        } catch (error) {
            logMessage('Warning: Index creation failed: ' + error.message);
        } finally {
            if (indexConnection) {
                await indexConnection.close();
            }
        }
    } catch (error) {
        logMessage('Failed to initialize Oracle pool: ' + error.message);
        throw error;
    }
}

// Configure winston to create a new log file daily for all logs
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: () => moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss')
        }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.DailyRotateFile({
            filename: path.join('logs', 'application', 'application-%DATE%.log'),
            datePattern: 'DD-MM-YYYY',
            maxFiles: '30d'
        }),
        new winston.transports.DailyRotateFile({
            filename: path.join('logs', 'errors', 'error-%DATE%.log'),
            datePattern: 'DD-MM-YYYY',
            level: 'error',
            maxFiles: '30d'
        }),
        new winston.transports.Console()
    ]
});

// Function to log messages
function logMessage(message, level = 'info') {
    logger.log({ level, message });
}

// Create an https agent that allows self-signed certificates
const agent = new https.Agent({
    rejectUnauthorized: false
});

// MD5 encryption method
function md5(val) {
    return crypto(val).toString();
}

// Map to track the last sent time for each error type
const lastErrorEmailSentTime = new Map();
const lastAuthErrorEmailSentTime = new Map();
let firstLoginAttemptFailed = false;

// Map to track the last sent time for first login errors
const lastFirstLoginErrorEmailSentTime = new Map();

// Add error notification tracking
const errorNotificationTracker = {
    counts: new Map(),
    lastSent: new Map(),
    pendingNotifications: new Map(),
    maxNotifications: 5,
    notificationWindow: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
    delayTime: 60 * 60 * 1000, // 1 hour in milliseconds

    incrementCount: function(errorKey) {
    const now = Date.now();
        const count = this.counts.get(errorKey) || 0;
        this.counts.set(errorKey, count + 1);
    },

    shouldSendNotification: function(errorKey) {
        const now = Date.now();
        const lastSentTime = this.lastSent.get(errorKey) || 0;
        const count = this.counts.get(errorKey) || 0;

        // Reset count if 24 hours have passed since last notification
        if (now - lastSentTime > this.notificationWindow) {
            this.counts.set(errorKey, 0);
            return true;
        }

        return count < this.maxNotifications;
    },

    updateLastSent: function(errorKey) {
        this.lastSent.set(errorKey, Date.now());
    },

    addPendingNotification: function(errorKey, timeoutId) {
        this.pendingNotifications.set(errorKey, timeoutId);
    },

    cancelPendingNotification: function(errorKey) {
        const timeoutId = this.pendingNotifications.get(errorKey);
        if (timeoutId) {
            clearTimeout(timeoutId);
            this.pendingNotifications.delete(errorKey);
            logMessage(`Cancelled pending notification for error: ${errorKey}`, 'info');
        }
    }
};

// Add database inactivity tracking
let lastRecordInsertTime = Date.now();

// Modify sendErrorNotification to handle error reoccurrence
function sendErrorNotification(error) {
    const errorKey = error.message;
    
    // Check if we should send this notification
    if (!errorNotificationTracker.shouldSendNotification(errorKey)) {
        logMessage(`Skipping error notification for: ${error.message} - maximum notifications reached for 24 hours`, 'info');
        return;
    }

    // Increment the error count
    errorNotificationTracker.incrementCount(errorKey);

    // If there's already a pending notification for this error, don't create another one
    if (errorNotificationTracker.pendingNotifications.has(errorKey)) {
        logMessage(`Error reoccurred within delay period: ${error.message}`, 'info');
            return;
        }

    // Delay sending the email for 1 hour
    const timeoutId = setTimeout(() => {
        const today = moment().tz('Africa/Nairobi').format('DD-MM-YYYY');
        const logFilePath = path.join('logs', 'errors', `error-${today}.log`);

        if (fs.existsSync(logFilePath)) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: process.env.NOTIFY_EMAIL,
                subject: `KUTRRH DSS-HMIS Attendance Logs Synchronization - Error Notification`,
                text: `
An error occurred: ${error.message}

Context:
The error occurred while processing access control logs. Please check the attached log file for more details.

Suggested Actions:
1. Review the attached log file to identify the root cause.
2. Check the system status and ensure all services are running.
3. Restart the application if necessary.

System Status:
- Memory Usage: ${Math.round(require('os').totalmem() / 1024 / 1024)}MB
- Time Since Last Record Insert: ${Math.round((Date.now() - lastRecordInsertTime) / (1000 * 60))} minutes

Contact Information:
For further assistance, please contact the technical support team.

Documentation:
For troubleshooting steps, please refer to the [Troubleshooting Guide] (https://drive.google.com/file/d/1sdIAic84WpounI3jAnp17gUhAhJuFics/view?usp=sharing).

${createEmailSignature()}
                `,
                attachments: [
                    {
                        filename: `error-${today}.log`,
                        path: logFilePath,
                        contentType: 'text/plain'
                    }
                ]
            };

            transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    logMessage('Error sending email: ' + err.message, 'error');
                    logEmailActivity(`Failed to send email: ${err.message}`);
                } else {
                    logMessage('Email sent: ' + info.response);
                    logEmailActivity(`Email sent: ${info.response}`);
                    errorNotificationTracker.updateLastSent(errorKey);
                }
                // Clear the pending notification after sending
                errorNotificationTracker.pendingNotifications.delete(errorKey);
            });
        } else {
            logMessage(`Log file not found: ${logFilePath}`, 'info');
            errorNotificationTracker.pendingNotifications.delete(errorKey);
        }
    }, errorNotificationTracker.delayTime);

    // Store the timeout ID for potential cancellation
    errorNotificationTracker.addPendingNotification(errorKey, timeoutId);
}

// Add a function to check for error reoccurrence
function checkErrorReoccurrence() {
    const now = Date.now();
    errorNotificationTracker.pendingNotifications.forEach((timeoutId, errorKey) => {
        // If the error hasn't reoccurred within the delay period, cancel the notification
        if (now - errorNotificationTracker.lastSent.get(errorKey) > errorNotificationTracker.delayTime) {
            errorNotificationTracker.cancelPendingNotification(errorKey);
        }
    });
}

// Schedule error reoccurrence check
setInterval(checkErrorReoccurrence, 5 * 60 * 1000); // Check every 5 minutes

// Add tracker for second authentication error
let secondAuthErrorFirstTimestamp = null;
let secondAuthErrorTimer = null;
const SECOND_AUTH_ERROR_NOTIFY_DELAY = 24 * 60 * 60 * 1000; // 24 hours in ms

// Modify handleAuthenticationError to only focus on second authentication errors and 24h rule
function handleAuthenticationError(error, isSecondAuth = false) {
    const errorKey = 'SECOND_AUTH_ERROR';
    const now = Date.now();

    if (isSecondAuth) {
        if (!secondAuthErrorFirstTimestamp) {
            // First occurrence of second authentication error
            secondAuthErrorFirstTimestamp = now;
            // Start a timer to send notification if error persists for 24 hours
            if (secondAuthErrorTimer) clearTimeout(secondAuthErrorTimer);
            secondAuthErrorTimer = setTimeout(() => {
                // If error still persists after 24 hours, send notification
                if (secondAuthErrorFirstTimestamp && (Date.now() - secondAuthErrorFirstTimestamp >= SECOND_AUTH_ERROR_NOTIFY_DELAY)) {
            sendErrorNotification(error);
                    // Reset tracker after sending
                    secondAuthErrorFirstTimestamp = null;
                    secondAuthErrorTimer = null;
        }
            }, SECOND_AUTH_ERROR_NOTIFY_DELAY);
        }
        // If error is resolved before 24 hours, reset tracker (call this on successful auth)
    } else {
        // For first authentication errors, just log or handle as before (no email)
        logMessage('First authentication error occurred, will retry', 'info');
    }
}

// Call this function on successful second authentication to reset the tracker
function resetSecondAuthErrorTracker() {
    if (secondAuthErrorTimer) clearTimeout(secondAuthErrorTimer);
    secondAuthErrorFirstTimestamp = null;
    secondAuthErrorTimer = null;
}

// Function to handle first login errors
function handleFirstLoginError() {
    const errorKey = 'FIRST_LOGIN_ERROR';
    const now = Date.now();
    const sixHours = 6 * 60 * 60 * 1000;

    logMessage('First login response does not contain valid realm, randomKey, or public key.', 'warn');

    if (!lastFirstLoginErrorEmailSentTime.has(errorKey) || (now - lastFirstLoginErrorEmailSentTime.get(errorKey) >= sixHours)) {
        sendErrorNotification(new Error('First login error persists for 6 hours'));
        lastFirstLoginErrorEmailSentTime.set(errorKey, now);
    }
}

// --- Token Keepalive and Update Logic ---
let tokenRateInterval = null;
let keepAliveInterval = null;
let tokenDuration = null;
let tokenRate = null;

async function keepTokenAlive() {
    try {
        const response = await axios.put(
            `${DSS_API_BASE}/brms/api/v1.0/accounts/keepalive`,
            { token },
            {
                httpsAgent: agent,
                headers: {
                    'X-Subject-Token': token,
                    'Content-Type': 'application/json;charset=UTF-8',
                },
            }
        );
        if (response.data && response.data.data) {
            const data = response.data.data;
            if (data.token) {
                token = data.token;
                logMessage('Token keep-alive successful, token updated.');
            } else {
                logMessage('Token keep-alive successful, no token update.');
            }
            if (data.duration) {
                tokenDuration = data.duration;
            }
            if (data.tokenRate) {
                tokenRate = data.tokenRate;
            }
        } else {
            logMessage('Token keep-alive: No data in response.');
        }
    } catch (error) {
        logMessage('Token keep-alive failed: ' + error.message, 'error');
        handleAuthenticationError(error, true);
    }
}

async function updateToken() {
    try {
        const response = await axios.post(
            `${DSS_API_BASE}/brms/api/v1.0/accounts/updateToken`,
            {},
            {
                httpsAgent: agent,
                headers: {
                    'X-Subject-Token': token,
                    'Content-Type': 'application/json;charset=UTF-8',
                },
            }
        );
        if (response.data && response.data.data) {
            const data = response.data.data;
            if (data.token) {
                token = data.token;
                logMessage('Token updated via updateToken endpoint.');
            }
            if (data.credential) {
                subjectToken = data.credential;
            }
            if (data.duration) {
                tokenDuration = data.duration;
            }
            if (data.tokenRate) {
                tokenRate = data.tokenRate;
            }
        } else {
            logMessage('updateToken: No data in response.');
        }
    } catch (error) {
        logMessage('updateToken failed: ' + error.message, 'error');
        handleAuthenticationError(error, true);
    }
}

function scheduleTokenTasks() {
    // Clear previous intervals if any
    if (keepAliveInterval) clearInterval(keepAliveInterval);
    if (tokenRateInterval) clearInterval(tokenRateInterval);
    // Schedule keepalive with 95% safety margin
    let keepAliveMs = (tokenDuration && tokenDuration > 0) ? tokenDuration * 1000 * 0.95 : 30 * 1000;
    keepAliveInterval = setInterval(keepTokenAlive, keepAliveMs);
    // Schedule updateToken if tokenRate is provided, also with 95% safety margin
    if (tokenRate && tokenRate > 0) {
        let tokenRateMs = tokenRate * 1000 * 0.95;
        tokenRateInterval = setInterval(updateToken, tokenRateMs);
    }
}

// Exponential backoff settings
let authBackoff = 60000; // Start with 1 minute
const maxBackoff = 30 * 60 * 1000; // 30 minutes
let consecutiveAuthFailures = 0;
let consecutive429Failures = 0;

// Enhanced authentication with exponential backoff
async function robustAuthenticate() {
    try {
        await authenticate(); // your existing authenticate function
        authBackoff = 60000; // reset on success
        consecutiveAuthFailures = 0;
        resetSecondAuthErrorTracker();
    } catch (err) {
        consecutiveAuthFailures++;
        logMessage('Authentication failed, will retry in ' + Math.round(authBackoff / 60000) + ' minutes', 'error');
        handleAuthenticationError(err, true);
        setTimeout(robustAuthenticate, authBackoff);
        authBackoff = Math.min(authBackoff * 2, maxBackoff);
    }
}

// 1. Define the original authenticate function
async function authenticate() {
    try {
        const firstLogin = await axios.post(`${DSS_API_BASE}/brms/api/v1.0/accounts/authorize`, {
            userName: DSS_USERNAME,
            clientType: DSS_CLIENT_TYPE,
        }, {
            httpsAgent: agent,
            maxRedirects: 5,
            validateStatus: (status) => status === 200 || status === 301 || status === 401,
            headers: {
                'Accept-Language': 'en',
                'Content-Type': 'application/json;charset=UTF-8',
                'User-Agent': 'Node.js App',
                'Referer': `${DSS_API_BASE}/brms`,
                'Time-Zone': process.env.TIME_ZONE,
            }
        });

        if (firstLogin.data.realm && firstLogin.data.randomKey && firstLogin.data.publickey) {
            realm = firstLogin.data.realm;
            randomKey = firstLogin.data.randomKey;
            publicKey = firstLogin.data.publickey;
            logMessage(`First login successful. Random Key: ${randomKey}`, 'info');
        } else {
            handleFirstLoginError(); // Handle the first login error
            return; // Exit early if the first login doesn't provide necessary data
        }

        const temp1 = md5(DSS_PASSWORD);
        const temp2 = md5(DSS_USERNAME + temp1);
        const temp3 = md5(temp2);
        const temp4 = md5(DSS_USERNAME + ":" + realm + ":" + temp3);
        const signatureString = `${temp4}:${randomKey}`;
        const finalSignature = md5(signatureString);

        const requestData = {
            signature: finalSignature,
            userName: DSS_USERNAME,
            randomKey,
            clientType: DSS_CLIENT_TYPE,
        };

        const secondLogin = await axios.post(`${DSS_API_BASE}/brms/api/v1.0/accounts/authorize`, requestData, {
            httpsAgent: agent,
            headers: {
                'Accept-Language': 'en',
                'Content-Type': 'application/json;charset=UTF-8',
                'User-Agent': 'Node.js App',
                'Referer': `${DSS_API_BASE}/brms`,
                'Time-Zone': process.env.TIME_ZONE,
            }
        });

        token = secondLogin.data.token;
        subjectToken = secondLogin.data.credential;

        if (!token) {
            logMessage('Second login failed: Token is undefined.', 'error');
            handleAuthenticationError(new Error('Second login failed: Token is undefined.'), true); // Only track second auth errors
            throw new Error('Second login failed: Token is undefined.');
        }

        // On successful second authentication, reset the tracker
        resetSecondAuthErrorTracker();

        logMessage(`Token obtained successfully: ${token}`);
    } catch (error) {
        logMessage('Authentication failed during second login: ' + error.message, 'error');
        handleAuthenticationError(error, true); // Only track second auth errors
        throw error;
    }
}

// Add batch size configuration
const BATCH_CONFIG = {
    fetchSize: 1000,
    insertBatchSize: 500,
    maxRetries: 3
};

// Add memory and performance configurations
const PERFORMANCE_CONFIG = {
    memory: {
        maxHeapUsage: 512 * 1024 * 1024,
        gcThreshold: 0.7
    },
    batch: {
        recentBatchSize: 50,
        historyBatchSize: 200,
        maxRetries: 3,
        queryTimeout: 45000
    },
    timeWindows: {
        recent: 2 * 60 * 60,
        history: 24 * 60 * 60
    },
    intervals: {
        recentRecords: 120000,
        historicalRecords: 600000,
        delayBetweenChunks: 200
    }
};

// Split fetchAccessLogs into two functions - one for recent and one for historical records
async function fetchRecentAccessLogs() {
    try {
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const startTime = currentTimestamp - PERFORMANCE_CONFIG.timeWindows.recent;
        
        await fetchWithBackoff(() => fetchLogsInTimeWindow(
            startTime, 
            currentTimestamp, 
            PERFORMANCE_CONFIG.batch.recentBatchSize,
            'recent'
        ));
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
        
        await fetchWithBackoff(() => fetchLogsInTimeWindow(
            startTime, 
            recentStartTime, 
            PERFORMANCE_CONFIG.batch.historyBatchSize,
            'historical'
        ));
    } catch (error) {
        logMessage('Error fetching historical access logs: ' + error.message);
        handleFetchError(error);
    }
}

async function fetchLogsInTimeWindow(startTime, endTime, batchSize, type) {
    let page = 1;
    let hasMoreRecords = true;
    let totalProcessed = 0;

    while (hasMoreRecords) {
        const payload = {
            page: page.toString(),
            pageSize: batchSize.toString(),
            startTime: startTime.toString(),
            endTime: endTime.toString(),
        };

        try {
            logMessage(`Fetching logs from DSS: startTime=${startTime}, endTime=${endTime}`);
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
                logMessage(`Fetched ${records.length} records from DSS for ${type} logs`);
                if (records.length > 0) {
                    await processRecordsBatch(records, type);
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
            if (error.response && error.response.status === 401) {
                logMessage('Authentication error, re-authenticating...', 'error');
                await authenticate();
            } else {
                logMessage(`Error fetching logs: ${error.message}`, 'error');
                sendErrorNotification(error);
                throw error;
            }
        }
    }
}

// Enhanced function to process records with overload handling
async function processRecordsBatch(records, type) {
    const batchStartTime = Date.now();
    let processed = 0;

    try {
        let chunkSize = type === 'recent' ? 25 : 50;
        for (let i = 0; i < records.length; i += chunkSize) {
            const chunk = records.slice(i, i + chunkSize);
            await compareWithDB(chunk);
            processed += chunk.length;

            await new Promise(resolve => 
                setTimeout(resolve, PERFORMANCE_CONFIG.intervals.delayBetweenChunks)
            );
        }
    } catch (error) {
        logErrorActivity(`Error processing ${type} batch: ${error.message}`);
        throw error;
    }

    const duration = Date.now() - batchStartTime;
    logMessage(`${type} batch processed ${processed} records in ${duration}ms`);
}

// Retry logic for operations
async function executeWithRetry(operation, maxRetries = 3) {
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;
            logMessage(`Attempt ${attempt} failed: ${error.message}`);
            if (attempt < maxRetries) {
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
            }
        }
    }
    logMessage(`All ${maxRetries} attempts failed.`);
    throw lastError;
}

// Add record counters
const recordCounters = {
    daily: 0,
    weekly: 0,
    monthly: 0,
    last24h: 0,
    resetDaily: function() {
        this.daily = 0;
    },
    resetWeekly: function() {
        this.weekly = 0;
    },
    resetMonthly: function() {
        this.monthly = 0;
    },
    resetLast24h: function() {
        this.last24h = 0;
    }
};

// Configure winston to create a new log file daily for record counts
const recordCountLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: () => moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss')
        }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.DailyRotateFile({
            filename: path.join('logs', 'records', 'record-counts-%DATE%.log'),
            datePattern: 'DD-MM-YYYY',
            maxFiles: '30d'
        })
    ]
});

// Function to log record counts
function logRecordCounts(type, count) {
    const message = `${type} records inserted: ${count}`;
    recordCountLogger.info(message);
    logMessage(message);
}

// Modify compareWithDB to include record counting
async function compareWithDB(logs) {
    return executeWithRetry(async () => {
        let connection;
        try {
            connection = await pool.getConnection();
            const chunkSize = 1000;
            let totalInserted = 0;
            
            for (let i = 0; i < logs.length; i += chunkSize) {
                const logsChunk = logs.slice(i, i + chunkSize);
                const bindPlaceholders = logsChunk.map((_, index) => `:${index + 1}`).join(',');
                const recordsToCheck = logsChunk.map(log => log.id);
                const result = await connection.execute(
                    `SELECT record_id FROM access_logs 
                     WHERE record_id IN (${bindPlaceholders})`,
                    recordsToCheck,
                    { autoCommit: true }
                );
                const existingRecords = new Set(result.rows.map(row => row[0]));
                const newRecords = logsChunk.filter(log => !existingRecords.has(log.id));
                
                if (newRecords.length > 0) {
                    newRecords.forEach(r => logMessage(`Attempting to insert record: ${r.id} at ${new Date(r.alarmTime * 1000)} | device: ${r.deviceName} | person: ${r.firstName} ${r.lastName}`));
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
                    
                    try {
                        const insertResult = await connection.executeMany(insertSql, insertBinds, {
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
                        });
                        
                        const insertedCount = insertResult.rowsAffected || 0;
                        if (insertedCount > 0) {
                            lastRecordInsertTime = Date.now();
                        }
                        totalInserted += insertedCount;
                        
                        // Update counters based on record age
                        const now = Date.now();
                        newRecords.forEach(record => {
                            const recordTime = record.alarmTime * 1000;
                            const ageInHours = (now - recordTime) / (1000 * 60 * 60);
                            
                            recordCounters.daily += 1;
                            if (ageInHours <= 24) {
                                recordCounters.last24h += 1;
                            }
                            if (ageInHours <= 168) { // 7 days
                                recordCounters.weekly += 1;
                            }
                            if (ageInHours <= 720) { // 30 days
                                recordCounters.monthly += 1;
                            }
                        });
                        
                        logMessage(`Batch inserted ${insertedCount} new records`);
                    } catch (insertError) {
                        logMessage(`Oracle insert error: ${insertError.message} | Records: ${JSON.stringify(insertBinds)}`, 'error');
                    }
                }
            }
            return totalInserted;
        } finally {
            if (connection) {
                try {
                    await connection.close();
                } catch (error) {
                    logErrorActivity('Error closing connection: ' + error.message);
                }
            }
        }
    });
}

// Add a cleanup function for graceful shutdown
async function cleanup() {
    try {
        if (pool) {
            await pool.close(10);
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

// Function to get the server IP address
function getServerIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'Unknown IP';
}

// Function to create an email signature
function createEmailSignature() {
    const serverIP = getServerIP();
    const user = process.env.DSS_USERNAME;
    const timestamp = moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss');
    return `\n\n--\nServer IP: ${serverIP}\nUser: ${user}\nTimestamp: ${timestamp}`;
}

const errorLogger = winston.createLogger({
    level: 'error',
    format: winston.format.combine(
        winston.format.timestamp({
            format: () => moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss')
        }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.DailyRotateFile({
            filename: path.join('logs', 'errors', 'error-%DATE%.log'),
            datePattern: 'DD-MM-YYYY',
            maxFiles: '30d'
        })
    ]
});

// Function to log error activities
function logErrorActivity(message) {
    errorLogger.error(message);
}

let serviceRecovered = false; // Flag to track service recovery

// Function to send service status email
function sendServiceStatusEmail(isRestored) {
    const serverIP = getServerIP();
    const user = process.env.DSS_USERNAME;
    const timestamp = moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss');
    const statusMessage = isRestored ? 'restored and is now running smoothly' : 'started or restarted successfully';

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: process.env.NOTIFY_EMAIL,
        subject: `KUTRRH DSS-HMIS Attendance Logs Synchronization - Service Notification`,
        text: `The Access Control Logs service has been ${statusMessage}.\n\n--\nServer IP: ${serverIP}\nUser: ${user}\nTimestamp: ${timestamp}`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            logMessage('Error sending service status email: ' + err.message);
            logEmailActivity(`Failed to send service status email: ${err.message}`);
        } else {
            logMessage('Service status email sent: ' + info.response);
            logEmailActivity(`Service status email sent: ${info.response}`);
        }
    });
}

let isServiceRunning = false;

// Modify init function to use the unified notification
async function init() {
    try {
        logMessage('System Information:');
        logMessage(`Total Memory: ${Math.round(require('os').totalmem() / 1024 / 1024)}MB`);
        logMessage(`CPUs: ${require('os').cpus().length}`);
        
        await initializePool();
        await robustAuthenticate();

        // Perform the first health check immediately
        await performHealthCheck();

        // Send service status email immediately
        sendServiceStatusEmail(!isServiceRunning); // Send restoration email if service was not running
        isServiceRunning = true; // Update service status

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
        sendErrorNotification(error);
        isServiceRunning = false; // Update service status
        await cleanup();
    }
}

// Configure Nodemailer with private email service
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Example usage in error handling
function handleFetchError(error) {
    logErrorActivity(`Fetch error: ${error.message}`);
    if (error.response) {
        logErrorActivity(`Response data: ${JSON.stringify(error.response.data)}`);
        logErrorActivity(`Response status: ${error.response.status}`);
    }
    sendErrorNotification(error);
}

// Health checks
async function performHealthCheck() {
    try {
        const connection = await pool.getConnection();
        await connection.execute('SELECT 1 FROM DUAL');
        logHealthCheck('Database connection is healthy');
        await connection.close();
    } catch (error) {
        logHealthCheck('Database health check failed: ' + error.message);
    }

    try {
        const temp1 = md5(DSS_PASSWORD);
        const temp2 = md5(DSS_USERNAME + temp1);
        const temp3 = md5(temp2);
        const temp4 = md5(DSS_USERNAME + ":" + realm + ":" + temp3);
        const signatureString = `${temp4}:${randomKey}`;
        const finalSignature = md5(signatureString);

        const requestData = {
            signature: finalSignature,
            userName: DSS_USERNAME,
            randomKey,
            clientType: DSS_CLIENT_TYPE,
        };

        console.log('Performing DSS API health check...'); // Debugging statement

        const response = await axios.post(`${DSS_API_BASE}/brms/api/v1.0/accounts/authorize`, requestData, {
            httpsAgent: agent,
            headers: {
                'Accept-Language': 'en',
                'Content-Type': 'application/json;charset=UTF-8',
            }
        });

        if (response.status === 200 && response.data.token) {
            logHealthCheck('DSS API health check successful: Token obtained');
        }
    } catch (error) {
        logHealthCheck('DSS API health check failed: ' + error.message);
    }
}

// Schedule health checks
setInterval(performHealthCheck, 60 * 60 * 1000); // Every hour

// Configure winston to create a new log file daily for health check logs
const healthCheckLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: () => moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss')
        }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.DailyRotateFile({
            filename: path.join('logs', 'health', 'health-%DATE%.log'),
            datePattern: 'DD-MM-YYYY',
            maxFiles: '30d'
        })
    ]
});

// Function to log health check activities
function logHealthCheck(message) {
    healthCheckLogger.info(message);
}

// Function to check and update missing records for the last month
async function checkAndUpdateMissingRecordsLastMonth() {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const oneMonthAgo = currentTimestamp - (30 * 24 * 60 * 60);

    try {
        await fetchWithBackoff(() => fetchLogsInTimeWindow(oneMonthAgo, currentTimestamp, BATCH_CONFIG.fetchSize, 'monthly'));
    } catch (error) {
        logMessage('Error checking and updating missing records for the last month: ' + error.message);
    }
}

// Schedule the check for missing records for the last month
setInterval(() => {
    checkAndUpdateMissingRecordsLastMonth().catch(error => {
        logMessage('Scheduled task for last month records failed: ' + error.message);
    });
}, 6 * 60 * 60 * 1000);

// Function to check and update all records within the last 60 days
async function checkAndUpdateAllRecordsWithinLast60Days() {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const sixtyDaysAgo = currentTimestamp - (60 * 24 * 60 * 60);

    try {
        await fetchWithBackoff(() => fetchLogsInTimeWindow(sixtyDaysAgo, currentTimestamp, BATCH_CONFIG.fetchSize, 'allWithinSixtyDays'));
    } catch (error) {
        logMessage('Error checking and updating all records within the last 60 days: ' + error.message);
    }
}

// Schedule the check for all records within the last 60 days
setInterval(() => {
    checkAndUpdateAllRecordsWithinLast60Days().catch(error => {
        logMessage('Scheduled task for all records within the last 60 days failed: ' + error.message);
    });
}, 24 * 60 * 60 * 1000);

// Function to check and update all records within the last 30 days
async function checkAndUpdateAllRecordsWithinLast30Days() {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const thirtyDaysAgo = currentTimestamp - (30 * 24 * 60 * 60);

    try {
        await fetchWithBackoff(() => fetchLogsInTimeWindow(thirtyDaysAgo, currentTimestamp, BATCH_CONFIG.fetchSize, 'allWithinThirtyDays'));
    } catch (error) {
        logMessage('Error checking and updating all records within the last 30 days: ' + error.message);
    }
}

// Schedule the check for all records within the last 30 days
setInterval(() => {
    checkAndUpdateAllRecordsWithinLast30Days().catch(error => {
        logMessage('Scheduled task for all records within the last 30 days failed: ' + error.message);
    });
}, 12 * 60 * 60 * 1000);

// Function to check and update all records within the last 7 days
async function checkAndUpdateAllRecordsWithinLast7Days() {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const sevenDaysAgo = currentTimestamp - (7 * 24 * 60 * 60);

    try {
        await fetchWithBackoff(() => fetchLogsInTimeWindow(sevenDaysAgo, currentTimestamp, BATCH_CONFIG.fetchSize, 'allWithinSevenDays'));
    } catch (error) {
        logMessage('Error checking and updating all records within the last 7 days: ' + error.message);
    }
}

// Function to check and update all records within the last month
async function checkAndUpdateAllRecordsWithinLastMonth() {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const oneMonthAgo = currentTimestamp - (30 * 24 * 60 * 60);

    try {
        logMessage('Starting monthly records verification and update...');
        await fetchWithBackoff(() => fetchLogsInTimeWindow(oneMonthAgo, currentTimestamp, BATCH_CONFIG.fetchSize, 'monthly'));
        logMessage('Monthly records verification and update completed successfully');
    } catch (error) {
        logMessage('Error checking and updating all records within the last month: ' + error.message, 'error');
        sendErrorNotification(error);
    }
}

// Schedule the check for all records within the last 7 days
setInterval(() => {
    checkAndUpdateAllRecordsWithinLast7Days().catch(error => {
        logMessage('Scheduled task for all records within the last 7 days failed: ' + error.message);
    });
}, 6 * 60 * 60 * 1000);

// Schedule the monthly records check to run every 24 hours
setInterval(() => {
    checkAndUpdateAllRecordsWithinLastMonth().catch(error => {
        logMessage('Scheduled monthly records check failed: ' + error.message, 'error');
    });
}, 24 * 60 * 60 * 1000);

const emailLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: () => moment().tz('Africa/Nairobi').format('DD-MM-YYYY HH:mm:ss')
        }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.DailyRotateFile({
            filename: path.join('logs', 'emails', 'email-%DATE%.log'),
            datePattern: 'DD-MM-YYYY',
            maxFiles: '30d'
        })
    ]
});

// Function to log email activities
function logEmailActivity(message) {
    emailLogger.info(message);
}

const emailLogDir = path.join('logs', 'emails');
if (!fs.existsSync(emailLogDir)) {
    fs.mkdirSync(emailLogDir, { recursive: true });
}

// Read the list of email addresses to send the daily log summary from environment variables
const summaryEmailList = process.env.SUMMARY_EMAIL_LIST ? process.env.SUMMARY_EMAIL_LIST.split(',') : [];

// Function to send combined daily access log summary (text + CSV, using created_at)
async function sendCombinedDailyAccessLogSummary() {
    const today = moment().tz('Africa/Nairobi').format('DD-MM-YYYY');
    const csvFilePath = path.join('logs', 'application', `application-summary-${today}.csv`);
    let last24hCount = 0, todayCount = 0, weekCount = 0, monthCount = 0;
    let connection;
    try {
        connection = await pool.getConnection();
        // Counts
        let result = await connection.execute(
            `SELECT COUNT(*) FROM access_logs WHERE created_at >= SYSDATE - 1`
        );
        last24hCount = result.rows[0][0];
        result = await connection.execute(
            `SELECT COUNT(*) FROM access_logs WHERE TRUNC(created_at) = TRUNC(SYSDATE)`
        );
        todayCount = result.rows[0][0];
        result = await connection.execute(
            `SELECT COUNT(*) FROM access_logs WHERE created_at >= SYSDATE - 7`
        );
        weekCount = result.rows[0][0];
        result = await connection.execute(
            `SELECT COUNT(*) FROM access_logs WHERE created_at >= SYSDATE - 30`
        );
        monthCount = result.rows[0][0];

        // CSV for today's records
        const recordsResult = await connection.execute(
            `SELECT * FROM access_logs WHERE TRUNC(created_at) = TRUNC(SYSDATE)`
        );
        const columns = recordsResult.metaData.map(col => col.name);
        const logEntries = recordsResult.rows.map(row => {
            const entry = {};
            columns.forEach((col, idx) => {
                entry[col] = row[idx];
            });
            return entry;
        });
        if (logEntries.length > 0) {
            const { Parser } = require('json2csv');
        const json2csvParser = new Parser();
        const csv = json2csvParser.parse(logEntries);
        fs.writeFileSync(csvFilePath, csv);
        } else {
            fs.writeFileSync(csvFilePath, 'No records inserted today.');
        }
    } catch (err) {
        logMessage('Error generating combined daily summary: ' + err.message, 'error');
        fs.writeFileSync(csvFilePath, 'Error generating CSV.');
    } finally {
        if (connection) await connection.close();
    }

    // Combine recipients
    const summaryEmailList = process.env.SUMMARY_EMAIL_LIST ? process.env.SUMMARY_EMAIL_LIST.split(',') : [];
    const notifyEmailList = process.env.NOTIFY_EMAIL ? process.env.NOTIFY_EMAIL.split(',') : [];
    const allRecipients = Array.from(new Set([...summaryEmailList, ...notifyEmailList])).join(', ');

    // Email
        const mailOptions = {
            from: process.env.EMAIL_USER,
        to: allRecipients,
            subject: `Daily Access Log Summary for ${today}`,
        text: `\nDaily Access Log Summary for ${today}\n\nRecords Inserted:\n- Last 24 Hours: ${last24hCount}\n- Today: ${todayCount}\n- This Week: ${weekCount}\n- This Month: ${monthCount}\n\nNote: Historical records (older than 24 hours) are tracked separately and included in the weekly and monthly counts.\n\n${createEmailSignature()}\n        `,
            attachments: [
                {
                    filename: `application-summary-${today}.csv`,
                    path: csvFilePath,
                    contentType: 'text/csv'
                }
            ]
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
            logMessage('Error sending combined daily access log summary: ' + err.message, 'error');
            } else {
            logMessage('Combined daily access log summary sent: ' + info.response);
            }
        });
}

// Schedule the combined daily summary to be sent at midnight
setInterval(() => {
    const now = moment().tz('Africa/Nairobi');
    if (now.hours() === 0 && now.minutes() === 0) {
        sendCombinedDailyAccessLogSummary();
    }
}, 60 * 1000); // Check every minute

// Function to send PM2 error logs via email
function sendPm2ErrorLogs() {
    const today = moment().tz('Africa/Nairobi').format('DD-MM-YYYY');
    const logFilePath = path.join('logs', 'pm2', 'err', 'err.log');

    if (fs.existsSync(logFilePath)) {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.NOTIFY_EMAIL,
            subject: `PM2 Error Logs for ${today}`,
            text: `Attached are the PM2 error logs for ${today}.`,
            attachments: [
                {
                    filename: `pm2-error-${today}.log`,
                    path: logFilePath,
                    contentType: 'text/plain'
                }
            ]
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                logMessage('Error sending PM2 error logs: ' + err.message, 'error');
            } else {
                logMessage('PM2 error logs sent: ' + info.response);
            }
        });
    } else {
        logMessage(`PM2 error log file not found for ${today}`, 'info');
    }
}

// Schedule the PM2 error log email to be sent at a specific time (e.g., midnight)
setInterval(() => {
    const now = new Date();
    if (now.getHours() === 0 && now.getMinutes() === 0) { // Check if it's midnight
        sendPm2ErrorLogs();
    }
}, 60 * 1000); // Check every minute

async function fetchWithBackoff(operation, maxRetries = 5) {
    let delay = 2000; // start with 2 seconds
    let local429Failures = 0;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            if (error.response && error.response.status === 429) {
                local429Failures++;
                consecutive429Failures++;
                let backoffDelay = Math.min(60000 * Math.pow(2, local429Failures), maxBackoff);
                logMessage(`429 received. Backing off for ${Math.round(backoffDelay / 60000)} minutes...`);
                await new Promise(res => setTimeout(res, backoffDelay));
                if (consecutive429Failures >= 3) {
                    logMessage('Too many 429 errors, pausing for 15 minutes before retrying...', 'error');
                    await new Promise(res => setTimeout(res, maxBackoff));
                    consecutive429Failures = 0;
                }
            } else {
                throw error;
            }
        }
    }
    throw new Error('Max retries reached for 429 errors');
}

// --- Custom Scheduling for Log Fetching ---
let isRecentCheckRunning = false;
let is24hCheckRunning = false;
let is7dCheckRunning = false;

async function safeFetchRecentLogs() {
    if (isRecentCheckRunning) {
        logMessage('Recent logs check is still running, skipping this interval.');
        return;
    }
    isRecentCheckRunning = true;
    try {
        const endTime = Math.floor(Date.now() / 1000);
        const startTime = endTime - 60 * 60; // last 1 hour
        logMessage(`Scheduled: Fetching logs for the past 1 hour: ${startTime} to ${endTime}`);
        await fetchWithBackoff(() => fetchLogsInTimeWindow(startTime, endTime, PERFORMANCE_CONFIG.batch.recentBatchSize, 'recent-1h'));
    } catch (error) {
        logMessage('Error in scheduled recent logs check: ' + error.message, 'error');
    } finally {
        isRecentCheckRunning = false;
    }
}

async function safeFetch24hLogs() {
    if (is24hCheckRunning) {
        logMessage('24h logs check is still running, skipping this interval.');
        return;
    }
    is24hCheckRunning = true;
    try {
        const endTime = Math.floor(Date.now() / 1000);
        const startTime = endTime - 24 * 60 * 60; // last 24 hours
        logMessage(`Scheduled: Fetching logs for the past 24 hours: ${startTime} to ${endTime}`);
        await fetchWithBackoff(() => fetchLogsInTimeWindow(startTime, endTime, PERFORMANCE_CONFIG.batch.historyBatchSize, 'history-24h'));
    } catch (error) {
        logMessage('Error in scheduled 24h logs check: ' + error.message, 'error');
    } finally {
        is24hCheckRunning = false;
    }
}

async function safeFetch7dLogs() {
    if (is7dCheckRunning) {
        logMessage('7d logs check is still running, skipping this interval.');
        return;
    }
    is7dCheckRunning = true;
    try {
        const endTime = Math.floor(Date.now() / 1000);
        const startTime = endTime - 7 * 24 * 60 * 60; // last 7 days
        logMessage(`Scheduled: Fetching logs for the past 7 days: ${startTime} to ${endTime}`);
        await fetchWithBackoff(() => fetchLogsInTimeWindow(startTime, endTime, PERFORMANCE_CONFIG.batch.historyBatchSize, 'history-7d'));
    } catch (error) {
        logMessage('Error in scheduled 7d logs check: ' + error.message, 'error');
    } finally {
        is7dCheckRunning = false;
    }
}

// Schedule the new intervals
setInterval(safeFetchRecentLogs, 10 * 60 * 1000); // every 10 minutes
setInterval(safeFetch24hLogs, 60 * 60 * 1000);    // every hour
setInterval(safeFetch7dLogs, 6 * 60 * 60 * 1000); // every 6 hours

init();
