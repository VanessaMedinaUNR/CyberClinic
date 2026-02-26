from pathlib import Path
import shutil
import pytest
import stat
import os

from storage_handler import StorageHandler


@pytest.fixture(scope='session')
def setup_storage(request):
    # Setup Storage for the entire test suite
    storage = StorageHandler()
    base_path = os.path.join('tests', 'temp', 'int')
    storage.base_path = os.path.abspath(base_path)
    ext_path = os.path.join('tests', 'temp', 'ext')
    storage.ext_path = os.path.abspath(ext_path)
    Path(storage.ext_path).mkdir(parents=True, exist_ok=True)
    Path(storage.base_path).mkdir(parents=True, exist_ok=True)

    # Mark the base path as read-only to match the behavior of PyInstaller's _MEIPASS directory
    if os.name == 'nt':
        import win32api, win32con
        win32api.SetFileAttributes(storage.base_path, win32con.FILE_ATTRIBUTE_READONLY)
    else:
        os.chmod(storage.base_path, os.stat(storage.base_path) & ~stat.S_IWRITE)
    
    # Teardown Storage after the entire test suite
    def teardown_storage():
        try:
            if os.name == 'nt':
                    win32api.SetFileAttributes(storage.base_path, win32con.FILE_ATTRIBUTE_NORMAL)
            else:
                os.chmod(storage.base_path, stat.S_IWRITE)
            shutil.rmtree(storage.base_path)
            shutil.rmtree(storage.ext_path)
        except Exception:
            pass
    request.addfinalizer(teardown_storage)
    
    return storage

class TestCStorageHandler:
    def test_fetch(self, setup_storage):
        storage: StorageHandler = setup_storage
        test_file = os.path.join(storage.base_path, 'test_fetch.txt')
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        fetched_file = storage.fetch('test_fetch.txt')
        assert fetched_file == test_file, f"Expected fetch to return '{test_file}', but got {fetched_file}"
        
        os.remove(test_file)

    @pytest.fixture(scope='function')
    def test_save_ext(self, setup_storage):
        storage: StorageHandler = setup_storage
        file_saved = storage.save_ext('test_save_ext.txt', "Test content")
        assert file_saved == True, "External File Failed to save"

    @pytest.mark.usefixtures("test_save_ext")
    def test_fetch_ext(self, setup_storage):
        storage: StorageHandler = setup_storage
        test_file = os.path.join(storage.ext_path, 'test_fetch_ext.txt')
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        fetched_file = storage.fetch_ext('test_fetch_ext.txt')
        assert fetched_file == test_file, f"Expected fetch_ext to return '{test_file}', but got {fetched_file}"
        
        os.remove(test_file)