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
def authed_cert(storage):
    cert = storage.fetch_ext(os.path.join('config', 'bundle.crt'))
    
    yield cert

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
            auth_tunnel = TunnelHandler(crt=auth_cert, host=server, port=auth_port)
            auth_tunnel.conn.send(b'CHECK')
            data = auth_tunnel.conn.recv(1024)
            assert data.decode() == 'TRUE', f"Expected to receive 'TRUE' from the authentication server, but got '{data.decode()}'"
            auth_tunnel.conn.send(b"CLOSE")
            auth_tunnel.close_tunnel()
        except Exception as e:
            pytest.fail(f"Failed to connect to authentication server, please ensure it is running and accessible at {server}:{auth_port}:\n{e}")

#    def test_authed_tunnel(self, authed_cert, server, authed_port, storage):
#        if authed_cert is None:
#            expected_path = os.path.join(storage.ext_path, 'config', 'bundle.crt')
#            pytest.skip(f'Please add the proper certificate to {expected_path} (This is generated on subnet authentication, so you may need to run the application and authenticate at least once before this certificate is generated)')
#        try:
#            authed_tunnel = TunnelHandler(crt=authed_cert, host=server, port=authed_port)
#            authed_tunnel.conn.send(b'CHECK')
#            data = authed_tunnel.conn.recv(1024)
#            assert data.decode() == 'TRUE', f"Expected to receive 'TRUE' from the authenticated server, but got '{data.decode()}'"
#            authed_tunnel.conn.send(b"CLOSE")
#            authed_tunnel.close_tunnel()
#        except Exception as e:
#            pytest.fail(f"Failed to connect to authenticated server, please ensure it is running and accessible at {server}:{authed_port}:\n{e}")
