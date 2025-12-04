#Cyber Clinic backend - Database connection and configuration

import psycopg2
import psycopg2.extras
import os
from contextlib import contextmanager
import logging

#database connection configuration using environment variables
#these values come from database.env file in docker-compose setup
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'database'),
    'port': os.environ.get('DB_PORT', 5432),
    'database': os.environ.get('DB_NAME', 'cyberclinic'),
    'user': os.environ.get('DB_USER', 'cyberclinic_user'),
    'password': os.environ.get('DB_PASS', 'dev_password_change_in_production')
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

#create global database manager instance
db_manager = DatabaseManager()

def init_db():
    #initialize database connection and create schema
    #this is called when the flask app starts up
    if db_manager.connect():
        return db_manager
    return False

def get_db():
    #get database manager instance for use in routes
    return db_manager
