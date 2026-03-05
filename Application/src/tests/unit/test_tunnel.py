import socket

import pytest
import os

from storage_handler import StorageHandler
from tunnel import TunnelHandler

@pytest.fixture
def storage():
    storage = StorageHandler()
    yield storage

@pytest.fixture
def auth_cert(storage):
    cert = storage.fetch(os.path.join('config', 'auth.crt'))
    
    yield cert

@pytest.fixture
def authed_cert_ca_key(storage):
    try:
        cert = storage.fetch_ext(os.path.join('config', 'client.crt'))
    except:
        cert = None
    try:
        ca = storage.fetch_ext(os.path.join('config', 'ca.crt'))
    except:
        ca = None
    try:
        key = storage.fetch_ext(os.path.join('config', 'client.key'))
    except:
        key = None

    yield (cert, ca, key)

@pytest.fixture
def server(request):
    return request.config.getoption("--server-host")

@pytest.fixture
def auth_port(request):
    return request.config.getoption("--auth-port")

@pytest.fixture
def authed_port(request):
    return request.config.getoption("--authed-port")

@pytest.mark.order(after="tests/unit/test_storage.py::TestCStorageHandler::test_fetch")
class TestTunnel:

    def test_auth_tunnel(self, auth_cert, server, auth_port, storage):
        if auth_cert is None:
            expected_path = os.path.join(storage.base_path, 'config', 'auth.crt')
            pytest.skip(f'Please add the proper server certificate to {expected_path}')
        try:
            auth_tunnel = TunnelHandler(host=server, port=auth_port, crt=auth_cert)
            auth_tunnel.conn.send(b'CHECK')
            data = auth_tunnel.conn.recv(1024)
            assert data.decode() == 'TRUE', f"Expected to receive 'TRUE' from the authentication server, but got '{data.decode()}'"
            auth_tunnel.conn.send(b"CLOSE")
            auth_tunnel.close_tunnel()
        except Exception as e:
            pytest.fail(f"Failed to connect to authentication server, please ensure it is running and accessible at {server}:{auth_port}:\n{e}")

    def test_authed_tunnel(self, authed_cert_ca_key, server, authed_port, storage):
        authed_cert, ca_cert, private_key = authed_cert_ca_key
        if not authed_cert or not ca_cert or not private_key:
            expected_path = os.path.join(storage.ext_path, 'config')
            found = [authed_cert, ca_cert, private_key]
            pytest.skip(f'''Please add the proper certificate, ca certificate, and private key to {expected_path}. \n
    found: {found} \n
    (This is generated on successful subnet authentication, so you may need to run the application and authenticate at least once before this certificate is generated)
            ''')
        try:
            authed_tunnel = TunnelHandler(host=server, port=authed_port, crt=authed_cert, key=private_key, ca=ca_cert)
            authed_tunnel.conn.send(b'CHECK')
            data = authed_tunnel.conn.recv(1024)
            assert data.decode() == 'TRUE', f"Expected to receive 'TRUE' from the authenticated server, but got '{data.decode()}'"
            authed_tunnel.conn.send(b"CLOSE")
            authed_tunnel.close_tunnel()
        except Exception as e:
            pytest.fail(f"Failed to connect to authenticated server, please ensure it is running and accessible at {server}:{authed_port}:\n{e}")
