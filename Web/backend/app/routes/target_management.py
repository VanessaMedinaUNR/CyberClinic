from flask import Blueprint, request, jsonify
import re
import socket
import ipaddress
from datetime import datetime
import logging
from ping3 import ping

#import our database manager for data operations
from app.database import get_db

#create blueprint for scan related endpoints
targets_bp = Blueprint('targets', __name__, url_prefix='/api/target')

#setup logging for scan operations
logger = logging.getLogger(__name__)

def validate_domain(domain):
    #validate that a domain name is properly formatted
    #checks for valid domain pattern and reasonable length
    if not domain or len(domain) > 253:
        return False
    
    #domain validation regex pattern - more flexible for real domains
    domain_pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*[A-Za-z0-9-]{1,63}(?<!-)$'
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


@targets_bp.route('/add-target', methods=['POST'])
def add_target():
    try:
        db = get_db()

        data = request.get_json()

        #get client_id from session (placeholder - will integrate with frontend auth later)
        client_id = data.get('client_id', 'cf3f847e-0bd7-4fa5-9e7d-38e2a803f6cd')
        if not client_id:
            return jsonify({'error': 'Authentication required'}), 400

        #validate required fields  
        required_fields = ['target_name', 'target_type', 'target_value']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
            

        target_name = data['target_name'].strip()
        target_type = data['target_type'].lower()
        target_value = data['target_value']
        public_facing = data['public_facing']
        verified = False
        verified_date = None

        if not public_facing == False and not public_facing == True :
            return jsonify({'error': f'Missing required field: public_facing'}), 400

        ip: ipaddress.IPv4Network

        if target_type == 'domain':
            if not validate_domain(target_value):
                return jsonify({'error': 'Invalid domain format'}), 400
            if public_facing:
                ip = ipaddress.IPv4Network(socket.gethostbyname(target_value))
                verified = True
                verified_date = datetime.now()
                logger.info(f'{target_value} Verified at: {verified_date}')

        elif target_type == 'ip':
            if not validate_ip_address(target_value):
                return jsonify({'error': 'Invalid IP address format'}), 400
            ip = ipaddress.IPv4Network(target_value, strict=False)
            if public_facing and ping(str(ip.network_address)) is not None:
                verified = True
                verified_date = datetime.now()
                logger.info(f'{target_value} Verified at: {verified_date}')
            

        elif target_type == 'range':
            if not validate_ip_range(target_value):
                return jsonify({'error': 'Invalid IP range format (use CIDR notation)'}), 400
            ip = ipaddress.IPv4Network(target_value, strict=False)
        

        else:
            return jsonify({'error': 'Invalid target type. Must be: domain, ip, or range'}), 400

        if verified:
            db.execute_command(
                """INSERT INTO network (client_id, subnet_name, subnet_ip, subnet_netmask, public_facing, verified, verification_date, creation_date) VALUES (%s, %s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                (client_id, target_name, str(ip.network_address), str(ip.netmask), public_facing)
            )
        else:
            db.execute_command(
                """INSERT INTO network (client_id, subnet_name, subnet_ip, subnet_netmask, public_facing, verified, creation_date) VALUES (%s, %s, %s, %s, %s, FALSE, CURRENT_TIMESTAMP)""",
                (client_id, target_name, str(ip.network_address), str(ip.netmask), public_facing)
            )
        if target_type == 'domain':
            db.execute_command(
                """INSERT INTO network_domains (domain, client_id, subnet_name) VALUES (%s, %s, %s)""",
                (target_value, client_id, target_name)
            )
        if not public_facing:
            db.execute_command(
                """INSERT INTO network_keys (client_id, subnet_name) VALUES (%s, %s)""",
                (client_id, target_name)
            )
        return jsonify({
            'success': True,
            'client_id': client_id,
            'target_id': target_name,
            'message': 'Target submitted successfully'
        }), 201
    except Exception as e:
        logger.error(f"Target submission failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500