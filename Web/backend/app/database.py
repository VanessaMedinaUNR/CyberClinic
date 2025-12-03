#Cyber Clinic backend - Database connection and configuration

import psycopg2
import psycopg2.extras
import os
from contextlib import contextmanager
import logging

#database connection configuration using environment variables
#these values come from database.env file in docker-compose setup
DB_CONFIG = {
    'host': os.environ.get('POSTGRES_HOST', 'localhost'),
    'port': os.environ.get('POSTGRES_PORT', 5432),
    'database': os.environ.get('POSTGRES_DB', 'cyberclinic'),
    'user': os.environ.get('POSTGRES_USER', 'cyberclinic_user'),
    'password': os.environ.get('POSTGRES_PASSWORD', 'dev_password_change_in_production')
}

#setup logging for database operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    #manages database connections and provides methods for common operations
    #this class handles connection pooling and error management
    
    def __init__(self):
        #connection will be established when first needed
        self._connection = None
        self.connected = False
    
    def connect(self):
        #establish connection to postgresql database
        #returns true if successful, false if connection fails
        try:
            self._connection = psycopg2.connect(**DB_CONFIG)
            self.connected = True
            logger.info("Database connection established successfully")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        #close database connection safely
        if self._connection:
            self._connection.close()
            self.connected = False
            logger.info("Database connection closed")
    
    @contextmanager
    def get_cursor(self):
        #context manager for database operations with automatic transaction handling
        #automatically commits on success, rolls back on error
        if not self.connected:
            if not self.connect():
                raise Exception("Cannot establish database connection")
        
        cursor = None
        try:
            cursor = self._connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            yield cursor
            self._connection.commit()
        except Exception as e:
            if self._connection:
                self._connection.rollback()
            logger.error(f"Database operation failed: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
    
    def execute_query(self, query, params=None):
        #execute a select query and return all results
        #used for fetching data from database
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def execute_single(self, query, params=None):
        #execute a select query and return single result
        #used when expecting exactly one row
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()
    
    def execute_command(self, query, params=None):
        #execute insert, update, or delete command
        #returns number of affected rows
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.rowcount

    def init_database_schema(self):
        #create database tables if they dont exist
        #this matches the UML design and schema requirements
        schema_sql = """
        -- create users table with backend-generated UUID and required fields
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            organization VARCHAR(100) NOT NULL,
            phone_number VARCHAR(20) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT true
        );
        
        -- create network_targets table matching NetworkTarget model  
        CREATE TABLE IF NOT EXISTS network_targets (
            id SERIAL PRIMARY KEY,
            target_name VARCHAR(100) NOT NULL,
            target_type VARCHAR(20) NOT NULL CHECK (target_type IN ('domain', 'ip', 'range')),
            target_value VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified BOOLEAN DEFAULT false,
            verification_date TIMESTAMP
        );
        
        -- create scan_jobs table matching ScanJob model
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            target_id INTEGER REFERENCES network_targets(id) ON DELETE CASCADE,
            scan_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            scan_config JSONB,
            results_path VARCHAR(500),
            error_message TEXT
        );
        
        -- create indexes for better query performance
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_id ON scan_jobs(user_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_network_targets_type ON network_targets(target_type);
        
        -- enable pgcrypto extension for password hashing
        CREATE EXTENSION IF NOT EXISTS pgcrypto;
        """
        
        try:
            with self.get_cursor() as cursor:
                cursor.execute(schema_sql)
            logger.info("Database schema initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Schema initialization failed: {e}")
            return False

#create global database manager instance
db_manager = DatabaseManager()

def init_db():
    #initialize database connection and create schema
    #this is called when the flask app starts up
    if db_manager.connect():
        return db_manager.init_database_schema()
    return False

def get_db():
    #get database manager instance for use in routes
    return db_manager
