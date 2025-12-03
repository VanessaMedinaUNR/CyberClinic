from app.models import user
import psycopg2
import os
from dotenv import load_dotenv
import socket
import ssl

def start_vpn_server(host, port, cert, key):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert, keyfile=key)
    bindsocket = socket.socket()
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"VPN server listening on {host}:{port}")
    while True:
        newsocket, fromaddr = bindsocket.accept()
        print(f"Connection from {fromaddr}")
        conn = context.wrap_socket(newsocket, server_side=True)
        try:
            data = conn.recv(1024)
            print(f"Received: {data}")
            if data:
                conn.sendall(b'Hello, VPN Client!')
        except Exception as e:
            print(f"Error: {e}")
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                print(f"Error during shutdown: {e}")
            conn.close()


if __name__ == '__main__':
    load_dotenv()
    
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_pass = os.getenv('DB_PASS')
    db_host = os.getenv('DB_HOST')
    db_port = os.getenv('DB_PORT')

    conn = psycopg2.connect(
        database=db_name,
        user=db_user,
        password=db_pass,
        host=db_host,
        port=db_port
    )

    vpn_host = os.getenv('VPN_HOST', '127.0.0.1')
    hostname = socket.gethostname()
    print(hostname)
    print(vpn_host)
    vpn_port = os.getenv('VPN_PORT', 6666)
    cert = os.getenv('VPN_CRT')
    key = os.getenv('VPN_KEY')

    start_vpn_server(hostname, int(vpn_port), cert, key)
