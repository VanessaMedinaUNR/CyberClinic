#Cyber Clinic backend - Main entry point
#CS 425 Team 13 - Fall 2025

from flask import Flask, jsonify, request
import os
import subprocess

#imported authentication routes from app package
from app.routes.auth import auth_bp

def create_app():
    #this creates our main flask web application
    #sets up basic configuration for development mode
    app = Flask(__name__)
    
    #get secret key from environment or use default for development
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = True
    
    #connect our authentication routes to the main app
    #this adds all the /api/auth/* endpoints like login and register
    app.register_blueprint(auth_bp)
    
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
                'GET /api/auth/users - list users (dev only)',
                'POST /api/scans/submit - submit scan request (coming soon)'
            ],
            'status': 'development',
            'database': 'not connected yet',
            'reptor': 'not integrated yet'
        })
    
    return app

if __name__ == '__main__':
    #this runs when we start the file directly (not imported)
    #starts up our web server so people can connect to it
    app = create_app()
    
    #server settings for docker containers
    host = '0.0.0.0'  #listen on all network interfaces so docker can connect
    port = 5000       #use port 5000 which is standard for flask apps
    debug = True      #auto reload when we change code files
    
    print("Starting Cyber Clinic Backend...")
    print(f"Server running on http://{host}:{port}")
    print("Debug mode enabled - auto-reload on code changes")
    
    app.run(host=host, port=port, debug=debug)
