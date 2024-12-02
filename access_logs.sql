CREATE DATABASE IF NOT EXISTS dss_access_logs;

USE dss_access_logs;

CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,                       -- Auto-increment primary key for each log entry
    record_id VARCHAR(255) NOT NULL,                          -- Unique record ID (from the API response)
    alarm_time DATETIME NOT NULL,                             -- The time the alarm was triggered (converted from Unix timestamp)
    device_code VARCHAR(255) NOT NULL,                        -- Code of the device that triggered the event
    device_name VARCHAR(255) NOT NULL,                        -- Name of the device that triggered the event
    channel_id VARCHAR(255) NOT NULL,                         -- ID of the channel (i.e., door or device)
    channel_name VARCHAR(255) NOT NULL,                       -- Name of the channel (e.g., Door 1)
    alarm_type_id INT NOT NULL,                               -- ID representing the alarm type (e.g., valid face unlock)
    alarm_type_name VARCHAR(255) NOT NULL,                    -- Name of the alarm type (e.g., Valid Face Unlock)
    person_id VARCHAR(255),                                   -- ID of the person (if applicable)
    first_name VARCHAR(255),                                  -- First name of the person (if applicable)
    last_name VARCHAR(255),                                   -- Last name of the person (if applicable)
    capture_image_url VARCHAR(255),                           -- URL to the captured image (if available)
    point_name VARCHAR(255),                                  -- Point name (i.e., the name of the door or area)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,           -- Timestamp of when the log entry was created
    UNIQUE(record_id)                                         -- Ensure record_id is unique in the table
);

-- Create index on record_id to improve search performance
CREATE INDEX idx_record_id ON access_logs (record_id);
