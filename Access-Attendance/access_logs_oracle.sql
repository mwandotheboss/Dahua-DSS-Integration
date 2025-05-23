DECLARE
  v_table_exists NUMBER;
BEGIN
  -- Check if table exists
  SELECT COUNT(*) INTO v_table_exists
  FROM user_tables
  WHERE table_name = 'ACCESS_LOGS';
  
  -- Create table if it doesn't exist
  IF v_table_exists = 0 THEN
    EXECUTE IMMEDIATE '
    CREATE TABLE access_logs (
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
    
    -- Create indexes
    EXECUTE IMMEDIATE 'CREATE INDEX idx_access_logs_alarm_time ON access_logs(alarm_time)';
    EXECUTE IMMEDIATE 'CREATE INDEX idx_access_logs_person_id ON access_logs(person_id)';
    
    -- Optional: Create sequence for record tracking
    EXECUTE IMMEDIATE '
    CREATE SEQUENCE access_logs_seq
        START WITH 1
        INCREMENT BY 1
        NOCACHE
        NOCYCLE';
        
    DBMS_OUTPUT.PUT_LINE('Table and indexes created successfully');
  ELSE
    DBMS_OUTPUT.PUT_LINE('Table already exists');
  END IF;
  
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
    RAISE;
END;
/

-- Grant necessary permissions (run as SYSDBA if needed)
GRANT SELECT, INSERT, UPDATE, DELETE ON access_logs TO your_application_user;
GRANT SELECT ON access_logs_seq TO your_application_user; 