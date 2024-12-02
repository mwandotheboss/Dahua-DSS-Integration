CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,                       -- Auto-increment primary key for each log entry
    record_id VARCHAR(255) NOT NULL,                          -- Unique record ID (from the API response)
    alarm_time DATETIME NOT NULL,                             -- The time the alarm was triggered (converted from Unix timestamp)
    device_code VARCHAR(255) NOT NULL,                        -- Code of the device that triggered the event
    device_name VARCHAR(255) NOT NULL,                        -- Name of the device that triggered the event
    channel_id VARCHAR(255) NOT NULL,                         -- ID of the channel (i.e., door or device)
    channel_name VARCHAR(255) NOT NULL,                       -- Name of the channel (e.g., Door 1)
    alarm_type_id INT DEFAULT NULL,                           -- ID representing the alarm type (e.g., valid face unlock) - can be NULL if not provided
    alarm_type_name VARCHAR(255) NULL,                        -- Name of the alarm type (e.g., Valid Face Unlock) - can be NULL if not provided
    person_id VARCHAR(255),                                   -- ID of the person (if applicable)
    first_name VARCHAR(255),                                  -- First name of the person (if applicable)
    last_name VARCHAR(255),                                   -- Last name of the person (if applicable)
    capture_image_url VARCHAR(255),                           -- URL to the captured image (if available)
    point_name VARCHAR(255),                                  -- Point name (i.e., the name of the door or area)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP            -- Timestamp of when the log entry was created (defaults to current time)
);
