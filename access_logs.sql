CREATE DATABASE IF NOT EXISTS access_control;

USE access_control;

CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    card_number VARCHAR(255) NOT NULL,
    access_point VARCHAR(255) NOT NULL,
    access_time DATETIME NOT NULL
);
