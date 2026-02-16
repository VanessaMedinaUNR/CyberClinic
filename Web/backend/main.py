#Cyber Clinic backend - Main entry point
from app.scan_worker import start_scan_worker, stop_scan_worker
from standalone_handler import start_standalone_handler
from app.routes.target_management import targets_bp
from app.routes.standalone import standalone_bp
#from app.routes.reports import reports_bp
from app.routes.scans import scans_bp
from app.routes.auth import auth_bp
from flask import Flask, jsonify
from flask_cors import CORS
import subprocess
import atexit
import os


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
    #app.register_blueprint(reports_bp)
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
    
    #parse arguments
    import argparse
    parser = argparse.ArgumentParser(description="Main CyberClinic Backend Entrypoint")
    parser.add_argument('--regen-certs', action='store_true', help='Regenerate keys and certificates')
    args = parser.parse_args()
    if args.regen_certs:
        print("Generating keys and certificates...")
        curdir = os.path.dirname(__file__)
        result = subprocess.run([os.path.join(curdir, 'generate_certs')], capture_output=True, text=True)
        print("Return code:", result.returncode)
    #start standalone handler
    print("Starting Standalone Handler...")

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
    
    #starts up our web server so people can connect to it
    app = create_app()
    CORS(app)
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