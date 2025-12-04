#Cyber Clinic backend - Scan management routes

from flask import Blueprint, request, jsonify
import re
import socket
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
    
    #domain validation regex pattern - more flexible for real domains
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
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
        #get client_id from session (placeholder - will integrate with auth later)
        client_id = user_id = data.get('client_id', 1)
        
        #validate required fields  
        required_fields = ['target_name', 'target_type', 'target_value', 'scan_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400

        target_name = data['target_name'].strip()
        target_type = data['target_type'].lower()
        target_value = data['target_value'].strip()
        scan_type = data['scan_type']
        
        public_facing = True 
        ip: ipaddress.IPv4Network

        #validate target type and value
        if target_type == 'domain':
            if not validate_domain(target_value):
                return jsonify({'error': 'Invalid domain format'}), 400
            ip = ipaddress.IPv4Network(socket.gethostbyname(target_value))

        elif target_type == 'ip':
            if not validate_ip_address(target_value):
                return jsonify({'error': 'Invalid IP address format'}), 400
            ip = ipaddress.IPv4Network(target_value, strict=False)

        elif target_type == 'range':
            if not validate_ip_range(target_value):
                return jsonify({'error': 'Invalid IP range format (use CIDR notation)'}), 400
            ip = ipaddress.IPv4Network(target_value, strict=False)

        else:
            return jsonify({'error': 'Invalid target type. Must be: domain, ip, or range'}), 400
        
        #validate scan type
        valid_scan_types = ['nmap', 'nikto', 'full']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Invalid scan type. Must be one of: {", ".join(valid_scan_types)}'}), 400
        
        db = get_db()
        
        #check if target already exists in network_targets table  
        existing_target = db.execute_single(
            "SELECT * FROM network WHERE client_id = %s AND subnet_name = %s",
            (client_id, target_name)
        )
        
        if existing_target:
            target_name = existing_target['subnet_name']
            logger.info(f"Using existing target: {target_name}")
        else:
            #create new network target
            target_name = db.execute_single(
                """INSERT INTO network (client_id, subnet_name, subnet_ip, subnet_netmask, public_facing) 
                   VALUES (%s, %s, %s, %s, %s) RETURNING subnet_name""",
                (client_id, target_name, str(ip.network_address), str(ip.netmask), public_facing)
            )['subnet_name']
            
            if target_type == "domain":
                db.execute_single(
                """INSERT INTO network_domains (domain, client_id, subnet_name) 
                   VALUES (%s, %s, %s, %s, %s)""",
                (target_value, client_id, target_name)
                )
            logger.info(f"Created new target: {target_name}")
        
        #get user_id from session (placeholder - will integrate with auth later)
        user_id = data.get('user_id', 1) 

        scan_job_ids = []
        #create scan job
        if scan_type.lower() == "full":
            nmap_scan_config = {
                'target_type': target_type,
                'scan_options': data.get('scan_options', {}),
                'priority': data.get('priority', 'normal')
            }
            
            nmap_scan_job_id = db.execute_single(
                """INSERT INTO scan_jobs (client_id, subnet_name, scan_type, scan_config, status) 
                VALUES (%s, %s, %s, %s, 'pending') RETURNING id""",
                (client_id, target_name, 'nmap', str(nmap_scan_config))
            )['id']
            scan_job_ids.append(nmap_scan_job_id)

            nikto_scan_config = {
                'target_type': target_type,
                'scan_options': data.get('scan_options', {}),
                'priority': data.get('priority', 'normal')
            }
            
            nikto_scan_job_id = db.execute_single(
                """INSERT INTO scan_jobs (client_id, subnet_name, scan_type, scan_config, status) 
                VALUES (%s, %s, %s, %s, 'pending') RETURNING id""",
                (client_id, target_name, 'nikto', str(nikto_scan_config))
            )['id']
            scan_job_ids.append(nikto_scan_job_id)
        else:
            scan_config = {
                'target_type': target_type,
                'scan_options': data.get('scan_options', {}),
                'priority': data.get('priority', 'normal')
            }
            
            scan_job_id = db.execute_single(
                """INSERT INTO scan_jobs (client_id, subnet_name, scan_type, scan_config, status) 
                VALUES (%s, %s, %s, %s, 'pending') RETURNING id""",
                (client_id, target_name, scan_type, str(scan_config))
            )['id']
            scan_job_ids.append(scan_job_id)
        
        for job_id in scan_job_ids:
            logger.info(f"Created scan job: {job_id} for target: {target_name}")
        
        return jsonify({
            'success': True,
            'scan_job_ids': scan_job_ids,
            'target_id': target_name,
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
            """SELECT sj.*, nt.subnet_name, nt.target_value, c.client_name
               FROM scan_jobs sj 
               JOIN network nt ON sj.client_id = nt.client_id AND sj.subnet_name = nt.subnet_name
               JOIN client c ON sj.client_id = c.client_id
               WHERE sj.id = %s""",
            (scan_id)
        )
        
        if not scan_details:
            return jsonify({'error': 'Scan job not found'}), 404
        
        target_value = None
        target_type = None
        #determine target value and type
        domain = db.execute_single(
            """SELECT domain
            FROM network_domains
            WHERE client_id = %s, subnet_name = %s""",
            (scan_details['client_id'], scan_details['subnet_name'])
            )
        if domain:
            target_type = "domain"
            target_value = domain
        else:
            if scan_details["subnet_netmask"] == "255.255.255.255":
                target_type = "ip"
                target_value = scan_details["subnet_ip"]
            else:
                target_type = "range"
                subnet_ip = scan_details['subnet_ip']
                subnet_netmask = scan_details['subnet_netmask']
                target_value = ipaddress.IPv4Network(f'{subnet_ip}/{subnet_netmask}').compressed

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
                'type': target_type,
                'value': target_value
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
            where_conditions.append("sj.client_id = %s")
            params.append(int(user_filter))
        
        if scan_type_filter:
            where_conditions.append("sj.scan_type = %s")
            params.append(scan_type_filter)
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        #add limit and offset for pagination
        params.extend([limit, offset])
        
        query = f"""
            SELECT sj.*, nt.subnet_name, nt.subnet_ip, nt.subnet_netmask, c.client_id
            FROM scan_jobs sj 
            JOIN network nt ON sj.client_id = nt.client_id AND sj.subnet_name = nt.subnet_name
            JOIN client c ON sj.client_id = c.client_id
            {where_clause}
            ORDER BY sj.created_at DESC
            LIMIT %s OFFSET %s
        """
        
        scans = db.execute_query(query, params)
        
        #format scan list for response
        scan_list = []
        for scan in scans:
            target_type = None
            target_value = None

            domain = db.execute_single(
                """SELECT domain
                FROM network_domains
                WHERE client_id = %s AND subnet_name = %s""",
                (scan['client_id'], scans['subnet_name'])
                )
            if domain:
                target_type = "domain"
                target_value = domain
            else:
                if scan["subnet_netmask"] == "255.255.255.255":
                    target_type = "ip"
                    target_value = scan["subnet_ip"]
                else:
                    target_type = "range"
                    subnet_ip = scan['subnet_ip']
                    subnet_netmask = scan['subnet_netmask']
                    target_value = ipaddress.IPv4Network(f'{subnet_ip}/{subnet_netmask}').compressed
            scan_list.append({
                'scan_id': scan['id'],
                'status': scan['status'],
                'scan_type': scan['scan_type'],
                'target': {
                    'name': scan['target_name'],
                    'type': target_type,
                    'value': target_value
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
            'verified': True,
            'reachable': True,
            'authorized': True,
            'verification_method': 'placeholder',
            'timestamp': datetime.now().isoformat(),
            'notes': 'Development mode - verification bypassed'
        }
        
        #update database if target exists
        db = get_db()
        db.execute_command(
            "UPDATE network SET verified = true, verification_date = CURRENT_TIMESTAMP WHERE target_value = %s",
            (target_value,)
        )
        
        return jsonify({
            'success': True,
            'verification_result': verification_result
        })
        
    except Exception as e:
        logger.error(f"Target verification failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/results/<int:scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    #get the detailed results of a completed scan
    try:
        db = get_db()
        
        scan_details = db.execute_single(
            """SELECT sj.*, n.subnet_name as target_name
               FROM scan_jobs sj 
               LEFT JOIN network n ON sj.subnet_name = n.subnet_name AND sj.client_id = n.client_id
               WHERE sj.id = %s""",
            (scan_id,)
        )
        
        if not scan_details:
            return jsonify({'error': 'Scan job not found'}), 404
        
        if scan_details['status'] not in ['completed', 'failed']:
            return jsonify({
                'error': 'Scan results not available',
                'status': scan_details['status'],
                'message': 'Scan must be completed to view results'
            }), 400
        
        # Parse results from database
        results = {}
        if scan_details['results']:
            try:
                import json
                results = json.loads(scan_details['results']) if isinstance(scan_details['results'], str) else scan_details['results']
            except json.JSONDecodeError:
                results = {'raw_output': scan_details['results']}
        
        return jsonify({
            'scan_id': scan_details['id'],
            'status': scan_details['status'],
            'scan_type': scan_details['scan_type'],
            'target_name': scan_details['target_name'],
            'created_at': scan_details['created_at'].isoformat(),
            'started_at': scan_details['started_at'].isoformat() if scan_details['started_at'] else None,
            'completed_at': scan_details['completed_at'].isoformat() if scan_details['completed_at'] else None,
            'results': results,
            'error_message': scan_details['error_message']
        })
        
    except Exception as e:
        logger.error(f"Results retrieval failed for scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/dashboard', methods=['GET'])
def scan_dashboard():
    #get dashboard overview of all scans with status counts
    try:
        db = get_db()
        
        # Get status summary
        status_summary = db.execute_query(
            """SELECT status, COUNT(*) as count
               FROM scan_jobs
               GROUP BY status
               ORDER BY status""",
            ()
        )
        
        # Get recent scans
        recent_scans = db.execute_query(
            """SELECT sj.id, sj.status, sj.scan_type, sj.created_at,
                      n.subnet_name as target_name, nd.domain
               FROM scan_jobs sj
               LEFT JOIN network n ON sj.target_id = n.subnet_id
               LEFT JOIN network_domains nd ON n.subnet_id = nd.subnet_id
               ORDER BY sj.created_at DESC
               LIMIT 10""",
            ()
        )
        
        return jsonify({
            'status_summary': [{'status': row['status'], 'count': row['count']} for row in status_summary],
            'recent_scans': [{
                'scan_id': scan['id'],
                'status': scan['status'],
                'scan_type': scan['scan_type'],
                'target': scan['domain'] if scan['domain'] else scan['target_name'],
                'created_at': scan['created_at'].isoformat()
            } for scan in recent_scans]
        })
        
    except Exception as e:
        logger.error(f"Dashboard query failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500
