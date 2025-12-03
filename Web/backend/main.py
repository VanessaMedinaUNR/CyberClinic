#Cyber Clinic backend - Main entry point

from flask import Flask, jsonify, request
import os
import logging

#imported authentication routes from app package  
from app.routes.auth import auth_bp
#imported scan management routes
from app.routes.scans import scans_bp
#imported report generation routes
from app.routes.reports import reports_bp
#imported standalone app integration
from app.routes.standalone import standalone_bp
#imported database connection and initialization
from app.database import init_db
#imported models matching project UML design
from app.models.user import UserAccount, ScanJob, NetworkTarget

def create_app():
    #this creates our main flask web application
    #sets up basic configuration for development mode
    app = Flask(__name__)
    
    #get secret key from environment or use default for development
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = True
    
    #setup logging for the application
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    #initialize database connection and schema
    logger.info("Initializing database connection...")
    if init_db():
        logger.info("Database initialized successfully")
    else:
        logger.warning("Database initialization failed - running without database")
    
    #connect our route blueprints to the main app
    #authentication endpoints: /api/auth/*
    app.register_blueprint(auth_bp)
    #scan management endpoints: /api/scans/*
    app.register_blueprint(scans_bp)
    #report generation endpoints: /api/reports/*
    app.register_blueprint(reports_bp)
    #standalone app integration: /api/standalone/*
    app.register_blueprint(standalone_bp)
    
    #create a simple health check endpoint at the root URL
    @app.route('/')
    def health_check():
        #this endpoint tells us if our backend server is working
        #docker and other services can check this to see if we're online
        return jsonify({
            'status': 'running',
            'service': 'cyber-clinic-backend',
            'version': '1.0.0',
            'team': 'CS425-Team13'
        })
    
    #create an info endpoint that shows what our API can do
    @app.route('/api/info')
    def api_info():
        #check database connection status
        from app.database import get_db
        db_status = 'connected' if get_db().connected else 'disconnected'
        
        #check reptor availability
        try:
            from reptor import Reptor
            reptor_status = 'available'
        except ImportError:
            reptor_status = 'not installed'
        
        #this shows what endpoints are available
        return jsonify({
            'service': 'cyber-clinic-backend',
            'version': '1.0.0',
            'team': 'CS425-Team13',
            'status': 'development',
            'database': db_status,
            'reptor': reptor_status,
            'available_endpoints': {
                'health': 'GET / - health check',
                'info': 'GET /api/info - this info',
                'authentication': [
                    'POST /api/auth/register - user registration',
                    'POST /api/auth/login - user login'
                ],
                'scan_management': [
                    'POST /api/scans/submit - submit new scan request',
                    'GET /api/scans/status/<id> - get scan status',
                    'GET /api/scans/list - list all scans (with filters)',
                    'POST /api/scans/cancel/<id> - cancel pending scan',
                    'POST /api/scans/verify-target - verify target authorization'
                ],
                'report_generation': [
                    'POST /api/reports/generate/<id> - generate report for completed scan',
                    'GET /api/reports/download/<id> - download report file',
                    'GET /api/reports/list - list available reports'
                ],
                'standalone_integration': [
                    'POST /api/standalone/execute/<id> - execute scan via standalone app',
                    'GET /api/standalone/status - check standalone app status'
                ]
            }
        })
    
    return app

if __name__ == '__main__':
    #this runs when we start the file directly (not imported)
    #starts up our web server so people can connect to it
    app = create_app()
    
    #server settings for docker containers
    host = '0.0.0.0'
    port = 5000
    debug = True 
    
    print("Starting Cyber Clinic Backend...")
    print(f"Server running on http://{host}:{port}")
    print("Debug mode enabled - auto-reload on code changes")
    
    app.run(host=host, port=port, debug=debug)
