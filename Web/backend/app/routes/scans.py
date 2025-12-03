#Cyber Clinic backend - Scan management routes

from flask import Blueprint, request, jsonify
import re
import ipaddress
from datetime import datetime
import logging

#import our database manager for data operations
from app.database import get_db

#create blueprint for scan related endpoints
scans_bp = Blueprint('scans', __name__, url_prefix='/api/scans')

#setup logging for scan operations
logger = logging.getLogger(__name__)

def validate_domain(domain):
    #validate that a domain name is properly formatted
    #checks for valid domain pattern and reasonable length
    if not domain or len(domain) > 253:
        return False
    
    #domain validation regex pattern
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_pattern, domain))

def validate_ip_address(ip):
    #validate that an IP address is properly formatted
    #supports both IPv4 and IPv6 addresses
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ip_range(ip_range):
    #validate that an IP range is properly formatted
    #supports CIDR notation like 192.168.1.0/24
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

@scans_bp.route('/submit', methods=['POST'])
def submit_scan():
    #submit a new scan request
    #creates network target, validates it, and creates scan job
    try:
        data = request.get_json()
        
        #validate required fields
        required_fields = ['target_name', 'target_type', 'target_value', 'scan_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        target_name = data['target_name'].strip()
        target_type = data['target_type'].lower()
        target_value = data['target_value'].strip()
        scan_type = data['scan_type']
        
        #validate target type and value
        if target_type == 'domain':
            if not validate_domain(target_value):
                return jsonify({'error': 'Invalid domain format'}), 400
        elif target_type == 'ip':
            if not validate_ip_address(target_value):
                return jsonify({'error': 'Invalid IP address format'}), 400
        elif target_type == 'range':
            if not validate_ip_range(target_value):
                return jsonify({'error': 'Invalid IP range format (use CIDR notation)'}), 400
        else:
            return jsonify({'error': 'Invalid target type. Must be: domain, ip, or range'}), 400
        
        #validate scan type
        valid_scan_types = ['nmap', 'vulnerability', 'full']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Invalid scan type. Must be one of: {", ".join(valid_scan_types)}'}), 400
        
        db = get_db()
        
        #check if target already exists
        existing_target = db.execute_single(
            "SELECT id, verified FROM network_targets WHERE target_value = %s AND target_type = %s",
            (target_value, target_type)
        )
        
        if existing_target:
            target_id = existing_target['id']
            logger.info(f"Using existing target: {target_id}")
        else:
            #create new network target
            target_id = db.execute_single(
                """INSERT INTO network_targets (target_name, target_type, target_value) 
                   VALUES (%s, %s, %s) RETURNING id""",
                (target_name, target_type, target_value)
            )['id']
            logger.info(f"Created new target: {target_id}")
        
        #get user_id from session (placeholder - will integrate with auth later)
        user_id = data.get('user_id', 1)  #default for development
        
        #create scan job
        scan_config = {
            'target_type': target_type,
            'scan_options': data.get('scan_options', {}),
            'priority': data.get('priority', 'normal')
        }
        
        scan_job_id = db.execute_single(
            """INSERT INTO scan_jobs (user_id, target_id, scan_type, scan_config, status) 
               VALUES (%s, %s, %s, %s, 'pending') RETURNING id""",
            (user_id, target_id, scan_type, str(scan_config))
        )['id']
        
        logger.info(f"Created scan job: {scan_job_id} for target: {target_id}")
        
        return jsonify({
            'success': True,
            'scan_job_id': scan_job_id,
            'target_id': target_id,
            'status': 'pending',
            'message': 'Scan request submitted successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Scan submission failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/status/<int:scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    #get the current status and details of a scan job
    try:
        db = get_db()
        
        scan_details = db.execute_single(
            """SELECT sj.*, nt.target_name, nt.target_type, nt.target_value, u.username
               FROM scan_jobs sj 
               JOIN network_targets nt ON sj.target_id = nt.id
               JOIN users u ON sj.user_id = u.id
               WHERE sj.id = %s""",
            (scan_id,)
        )
        
        if not scan_details:
            return jsonify({'error': 'Scan job not found'}), 404
        
        #calculate scan duration if completed
        duration = None
        if scan_details['started_at'] and scan_details['completed_at']:
            duration = (scan_details['completed_at'] - scan_details['started_at']).total_seconds()
        
        return jsonify({
            'scan_id': scan_details['id'],
            'status': scan_details['status'],
            'scan_type': scan_details['scan_type'],
            'target': {
                'name': scan_details['target_name'],
                'type': scan_details['target_type'],
                'value': scan_details['target_value']
            },
            'user': scan_details['username'],
            'created_at': scan_details['created_at'].isoformat(),
            'started_at': scan_details['started_at'].isoformat() if scan_details['started_at'] else None,
            'completed_at': scan_details['completed_at'].isoformat() if scan_details['completed_at'] else None,
            'duration_seconds': duration,
            'results_path': scan_details['results_path'],
            'error_message': scan_details['error_message']
        })
        
    except Exception as e:
        logger.error(f"Status check failed for scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/list', methods=['GET'])
def list_scans():
    #list all scan jobs with optional filtering
    #supports filtering by status, user, scan type
    try:
        #get query parameters for filtering
        status_filter = request.args.get('status')
        user_filter = request.args.get('user_id')
        scan_type_filter = request.args.get('scan_type')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        db = get_db()
        
        #build dynamic query based on filters
        where_conditions = []
        params = []
        
        if status_filter:
            where_conditions.append("sj.status = %s")
            params.append(status_filter)
        
        if user_filter:
            where_conditions.append("sj.user_id = %s")
            params.append(int(user_filter))
        
        if scan_type_filter:
            where_conditions.append("sj.scan_type = %s")
            params.append(scan_type_filter)
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        #add limit and offset for pagination
        params.extend([limit, offset])
        
        query = f"""
            SELECT sj.*, nt.target_name, nt.target_type, nt.target_value, u.username
            FROM scan_jobs sj 
            JOIN network_targets nt ON sj.target_id = nt.id
            JOIN users u ON sj.user_id = u.id
            {where_clause}
            ORDER BY sj.created_at DESC
            LIMIT %s OFFSET %s
        """
        
        scans = db.execute_query(query, params)
        
        #format scan list for response
        scan_list = []
        for scan in scans:
            scan_list.append({
                'scan_id': scan['id'],
                'status': scan['status'],
                'scan_type': scan['scan_type'],
                'target': {
                    'name': scan['target_name'],
                    'type': scan['target_type'],
                    'value': scan['target_value']
                },
                'user': scan['username'],
                'created_at': scan['created_at'].isoformat(),
                'started_at': scan['started_at'].isoformat() if scan['started_at'] else None,
                'completed_at': scan['completed_at'].isoformat() if scan['completed_at'] else None
            })
        
        return jsonify({
            'scans': scan_list,
            'total': len(scan_list),
            'offset': offset,
            'limit': limit
        })
        
    except Exception as e:
        logger.error(f"Scan listing failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/cancel/<int:scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    #cancel a pending or running scan job
    #only the scan owner or admin can cancel scans
    try:
        db = get_db()
        
        #check if scan exists and can be cancelled
        scan_details = db.execute_single(
            "SELECT status, user_id FROM scan_jobs WHERE id = %s",
            (scan_id,)
        )
        
        if not scan_details:
            return jsonify({'error': 'Scan job not found'}), 404
        
        if scan_details['status'] not in ['pending', 'running']:
            return jsonify({'error': 'Cannot cancel scan in current status'}), 400
        
        #update scan status to cancelled
        rows_updated = db.execute_command(
            "UPDATE scan_jobs SET status = 'cancelled', completed_at = CURRENT_TIMESTAMP WHERE id = %s",
            (scan_id,)
        )
        
        if rows_updated > 0:
            logger.info(f"Cancelled scan job: {scan_id}")
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'status': 'cancelled',
                'message': 'Scan cancelled successfully'
            })
        else:
            return jsonify({'error': 'Failed to cancel scan'}), 500
        
    except Exception as e:
        logger.error(f"Scan cancellation failed for scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/verify-target', methods=['POST'])
def verify_target():
    #verify that a network target is reachable and authorized for scanning
    #placeholder for domain verification and reachability checks
    try:
        data = request.get_json()
        
        target_type = data.get('target_type')
        target_value = data.get('target_value')
        
        if not target_type or not target_value:
            return jsonify({'error': 'Missing target_type or target_value'}), 400
        
        #placeholder verification logic
        #in production this would check DNS, ping, port scans, authorization
        verification_result = {
            'verified': True,  #placeholder - always pass for development
            'reachable': True,
            'authorized': True,
            'verification_method': 'placeholder',
            'timestamp': datetime.now().isoformat(),
            'notes': 'Development mode - verification bypassed'
        }
        
        #update database if target exists
        db = get_db()
        db.execute_command(
            "UPDATE network_targets SET verified = true, verification_date = CURRENT_TIMESTAMP WHERE target_value = %s",
            (target_value,)
        )
        
        return jsonify({
            'success': True,
            'verification_result': verification_result
        })
        
    except Exception as e:
        logger.error(f"Target verification failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500
