module.exports = {
  apps: [{
    name: "dss-access-logs",
    script: "./Access-Attendance/access_control_logs_oracle.js",
    watch: false,
    instances: 1,
    autorestart: true,
    max_restarts: 10,
    min_uptime: "1m",
    max_memory_restart: "1G",
    env: {
      NODE_ENV: "production",
      // DSS API Configuration
      DSS_API_BASE: "https://10.80.17.7:443",
      DSS_USERNAME: "system",
      DSS_PASSWORD: "Admin@123",
      DSS_CLIENT_TYPE: "NODE_APP",
      // Other Settings
      TIME_ZONE: "Africa/Nairobi",
      // Oracle Database Configuration
      ORACLE_USER: "KUHATT",
      ORACLE_PASSWORD: "ATT$123$",
      ORACLE_CONNECT_STRING: "10.80.3.72:1521/OPERKEN"
    },
    error_file: "logs\\err.log",    // Note the Windows path separator
    out_file: "logs\\out.log",      // Note the Windows path separator
    log_file: "logs\\combined.log", // Note the Windows path separator
    time: true,
    merge_logs: true
  }]
}; 