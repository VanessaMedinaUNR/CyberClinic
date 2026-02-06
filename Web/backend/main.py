#Cyber Clinic backend - Main entry point

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import os
import atexit
import logging
from app.database import get_db
from app.routes.auth import auth_bp
from app.routes.scans import scans_bp
from app.routes.reports import reports_bp
from app.routes.standalone import standalone_bp
from app.routes.target_management import targets_bp
from app.scan_worker import start_scan_worker, stop_scan_worker

def create_app():
    #this creates our main flask web application
    #sets up basic configuration for development mode
    app = Flask(__name__)
    #get secret key from environment or use default for development
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG')
    #connect our authentication routes to the main app
    #this adds all the /api/auth/* endpoints like login and register
    app.register_blueprint(auth_bp)
    #add additional routes for full CyberClinic functionality
    app.register_blueprint(scans_bp) 
    app.register_blueprint(reports_bp)
    app.register_blueprint(standalone_bp)
    app.register_blueprint(targets_bp)
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
    #this runs when we start the file directly (not imported)
    #starts up our web server so people can connect to it
    app = create_app()
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY')
    jwt = JWTManager(app)

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

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
            "error": "Missing or invalid token",
            "code": "authorization_required"
        }), 401


    @jwt.expired_token_loader
    def handle_expired_token(jwt_header, jwt_payload):
        return jsonify({"error": "Session has expired", "code": "session_expired"}), 401


    @jwt.invalid_token_loader
    def handle_invalid_token(error):
        return jsonify({"error": "Invalid session", "code": "session_invalid"}), 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
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
    print("Starting background scan worker...")
    start_scan_worker()
    #register cleanup function to stop worker on exit
    atexit.register(stop_scan_worker)
    #server settings for docker containers
    host = os.environ.get('FLASK_SERVER')
    port = os.environ.get('FLASK_PORT')
    #disable debug in Docker to avoid I/O issues
    debug = os.environ.get('FLASK_ENV') == 'development' and not os.path.exists('/.dockerenv')
    
    print("Starting Cyber Clinic Backend...")
    print(f"Server running on http://{host}:{port}")
    print("Debug mode enabled - auto-reload on code changes")
    print("Scan worker running - will process scan jobs automatically")
    
    app.run(host=host, port=port, debug=debug)

# Done by Morales-Marroquin and Austin Finch