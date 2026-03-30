from flask import Blueprint, Flask, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
import logging
from app.database import get_db


saveCode_bp = Blueprint('ai', __name__, url_prefix='/api/saveCode')
logger = logging.getLogger(__name__)

#saving code from when a code scan is submitted, report_id is generated automatically

@jwt_required()
@saveCode_bp.route("/savecode", methods=["POST"])
def savecode():


    try:

        #get the data provided (code input and result) and if no data is provided then returns error message
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid or missing JSON"}), 400
        logger.info(data)


    
        #get user_id
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


@jwt_required()
@saveCode_bp.route("/savecode", methods=["GET"])
def get_saved_codes():


    try:
        
        #to get user identity
        user_id = get_jwt_identity()

        #connect database 
        db = get_db()
        
       
        #retrieve all scans from db, limited 10, and ordered by when it was created 
        results = db.execute(
            """SELECT code_input, report, report_id FROM codechecker_results WHERE user_id = %s ORDER BY created_at DESC LIMIT 10""",(user_id,)
        )
    
        #make the scans into a list, each row contains report_id, code_input, and report 
        scans=[]
        for row in results:
            scans.append({
                "report_id": row["report_id"],
                "code_input": row["code_input"],
                "report": row["report"]
            })

        #return success, scans are in JSON format
        return jsonify(scans), 200


    #server doesn't work
    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": "Internal server error"}), 500
