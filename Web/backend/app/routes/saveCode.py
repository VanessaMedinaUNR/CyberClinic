from flask import Blueprint, Flask, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
import logging
from app.database import get_db


saveCode_bp = Blueprint('ai', __name__, url_prefix='/api/saveCode')

#saving code from when a code scan is submitted, report_id is generated automatically

@jwt_required()
@saveCode_bp.route("/savecode", methods=["POST"])
def savecode():


    try:
        #get the data provided (code input and result)
        data = request.get_json()
        logger.info(data)
    
        
        code_input = data.get('code_input', '')
        report = data.get('report', '')
        user_id = get_jwt_identity()
       
        
        #make sure required information was provided 
        if not code_input or not report:
            return jsonify({
                'error': 'missing required fields',
                'required': ['code_input', 'report']
            }), 400

        #connect database 
        db = get_db()
        
        #check if code has been saved before 
        existing_code = db.execute_single(
            "SELECT code_input FROM codechecker_results WHERE code_input = %s AND user_id = %s", (code_input, user_id)
        )
        
        #if code exists in db then no need to save 
        if existing_code:
            return jsonify({"message": "Code already saved"}), 200
        
        #saves to db 
        db.execute_single(
            """INSERT INTO codechecker_results (code_input, report, user_id) 
            VALUES (%s, %s, %s)""",
            (code_input, report, user_id)
        )
    
        #return success
        return jsonify({"message": "Code saved successfully"}), 201

    #server doesn't work
    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": "Internal server error"}), 500
