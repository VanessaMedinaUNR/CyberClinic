#Cyber Clinic backend - Main entry point
from app.workers.report_worker import start_report_worker, stop_report_worker
from app.workers.scan_worker import start_scan_worker, stop_scan_worker
from standalone_handler import start_standalone_handler
from app.routes.target_management import targets_bp
from app.routes.standalone import standalone_bp
from app.database import get_db, block_jwt
from app.routes.reports import reports_bp
from flask_jwt_extended import JWTManager
from app.routes.scans import scans_bp
from app.routes.auth import auth_bp
from flask import Flask, jsonify
from app.routes.ai import ai_bp
from flask_cors import CORS
import logging
import atexit
import os

# setup logging for the application
logging_format = '%(asctime)s: %(name)s - %(levelname)s: %(message)s'
logger = logging.getLogger(__name__)

def create_app(debug=False):
    #this creates our main flask web application
    #sets up basic configuration for development mode
    app = Flask(__name__)
    #get secret key from environment or use default for development
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if debug:
        app.config['DEBUG'] = True
        logging.basicConfig(format=logging_format, level=logging.DEBUG, force=True)
    else:
        app.config['DEBUG'] = False
        logging.basicConfig(format=logging_format, level=logging.INFO, force=True)
    #connect our authentication routes to the main app
    #this adds all the /api/auth/* endpoints like login and register
    app.register_blueprint(auth_bp)
    #add additional routes for full CyberClinic functionality
    app.register_blueprint(scans_bp) 
    app.register_blueprint(reports_bp)
    app.register_blueprint(standalone_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(ai_bp)
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
        #this shows what endpoints are available
        return jsonify({
            'available_endpoints': [
                'GET / - health check',
                'GET /api/info - this info',
                'POST /api/auth/register - user registration (READY)',
                'POST /api/auth/login - user login (READY)', 
                'POST /api/scans/submit - submit scan request (READY)',
                'GET /api/scans/status/<id> - get scan status (READY)',
                'POST /api/reports/generate/<id> - generate report (READY)',
                'POST /api/standalone/execute/<id> - Austin\'s client integration (NOT READY)'
            ],
            'status': 'development',
            'database': 'connected',
            'reptor': 'not integrated yet'
        })

    return app

if __name__ == '__main__':
    #parse arguments
    import argparse
    parser = argparse.ArgumentParser(description="Main CyberClinic Backend Entrypoint")
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with auto-reload and verbose logging')
    args = parser.parse_args()
    
    app = create_app(debug=args.debug)
    logger.debug("Debug mode enabled - auto-reload on code changes")
    logger.info("Starting Cyber Clinic Backend...")
    
    #start standalone handler
    logger.info("Starting Standalone Handler...")

    auth_port = int(os.getenv('AUTH_PORT', 9999))
    auth_cert = os.getenv('AUTH_CRT', '/src/certs/auth.crt')
    auth_key = os.getenv('AUTH_KEY', '/src/certs/auth.key')
    auth_pass = os.getenv('AUTH_PASS', 'cyberclinicdev')

    authed_port = int(os.getenv('AUTHED_PORT', 9999))
    authed_cert = os.getenv('AUTHED_CRT', '/src/certs/authed.crt')
    authed_key = os.getenv('AUTHED_KEY', '/src/certs/authed.key')
    authed_pass = os.getenv('AUTHED_PASS', 'cyberclinicdev')
    
    start_standalone_handler(
        auth_port=auth_port,
        auth_cert=auth_cert,
        auth_key=auth_key,
        auth_pass=auth_pass,
        authed_port=authed_port,
        authed_cert=authed_cert,
        authed_key=authed_key,
        authed_pass=authed_pass
    )
    
    # Sets up CORS and JWT authentication for our API endpoints
    frontend = os.environ.get('FRONTEND_HOST', 'localhost')
    frontend_port = os.environ.get('FRONTEND_PORT', 3000)
    CORS(app, resources={r"/api/*": {"origins": f"*"}})

    app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY')
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_revoked(jwt_header, jwt_payload: dict):
        jti = jwt_payload['jti']
        
        try:
            db = get_db()
            blocked = db.execute_single(
                """SELECT id FROM blocked_jwt WHERE jti = %s""",
                (jti,)
            )
        except Exception as e:
            logger.error(e)
            return True
        return blocked is not None

    @jwt.unauthorized_loader
    def handle_unauthorized(error):
        return jsonify({
            "error": "You are access this resource",
            "code": "authorization_required"
        }), 401


    @jwt.expired_token_loader
    def handle_expired_token(jwt_header, jwt_payload):
        return jsonify({"error": "Session has expired", "code": "session_expired"}), 403
    
    @jwt.revoked_token_loader
    def handle_revoked_token(jwt_header, jwt_payload):
        return jsonify({"error": "Session has expired", "code": "session_expired"}), 403


    @jwt.invalid_token_loader
    def handle_invalid_token(invalid_token):
        logger.error(f"Invalid token received: {invalid_token}")
        return jsonify({"error": "Invalid session", "code": "session_invalid"}), 403
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        block_jwt(jwt_payload["jti"])
        return (
        jsonify(
            {
                "error": "Please sign in again.",
                "code": "fresh_token_required"
            }
        ),
        401,
    )
    
    #start the background scan worker
    logger.info("Starting background scan worker...")
    start_scan_worker(os.environ.get('SCAN_DIR'))
    #register cleanup function to stop worker on exit
    atexit.register(stop_scan_worker)
    logger.info("Scan worker running - will process scan jobs automatically")
    #start the background report worker
    logger.info("Starting background report worker...")
    start_report_worker(os.environ.get('REPORT_DIR'))
    #register cleanup function to stop worker on exit
    atexit.register(stop_report_worker)
    logger.info("Report worker running - will process report jobs automatically")
    #server settings for docker containers
    host = os.environ.get('FLASK_SERVER')
    port = os.environ.get('FLASK_PORT')
    #disable debug in Docker to avoid I/O issues
    debug = app.config['DEBUG'] and not os.path.exists('/.dockerenv')
    
    logger.info(f"Server running on http://{host}:{port}")
    
    app.run(host=host, port=port, debug=debug)

# Done by Morales-Marroquin and Austin Finch