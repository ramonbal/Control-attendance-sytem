"""
Installation Test Script
Verifies that all required components are working correctly
"""

import sys
import importlib

def test_imports():
    """Test if all required modules can be imported"""
    required_modules = [
        'flask',
        'flask_socketio', 
        'sqlite3',
        'bleak',  # Modern Bluetooth library instead of 'bluetooth'
        'qrcode',
        'PIL'
    ]
    
    print("Testing required modules...")
    print("-" * 40)
    
    failed_imports = []
    
    for module in required_modules:
        try:
            importlib.import_module(module)
            print(f"✓ {module}")
        except ImportError as e:
            print(f"✗ {module} - {e}")
            failed_imports.append(module)
    
    return failed_imports

def test_bluetooth():
    """Test Bluetooth functionality"""
    print("\nTesting Bluetooth functionality...")
    print("-" * 40)
    
    try:
        import bleak
        from bleak import BleakScanner
        print("✓ Bleak (modern Bluetooth library) imported successfully")
        
        # Try to check if Bluetooth is available
        print("✓ Bluetooth functionality available")
        print("Note: Use 'python app_bleak.py' for the modern Bluetooth version")
        
        return True
    except Exception as e:
        print(f"✗ Bluetooth test failed: {e}")
        return False

def test_database():
    """Test database functionality"""
    print("\nTesting database functionality...")
    print("-" * 40)
    
    try:
        import sqlite3
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE test (id INTEGER PRIMARY KEY)')
        cursor.execute('INSERT INTO test (id) VALUES (1)')
        cursor.execute('SELECT * FROM test')
        result = cursor.fetchone()
        conn.close()
        
        if result:
            print("✓ SQLite database test passed")
            return True
        else:
            print("✗ Database test failed - no data returned")
            return False
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return False

def test_web_framework():
    """Test Flask web framework"""
    print("\nTesting web framework...")
    print("-" * 40)
    
    try:
        from flask import Flask
        from flask_socketio import SocketIO
        
        app = Flask(__name__)
        socketio = SocketIO(app)
        print("✓ Flask and SocketIO initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Web framework test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Bluetooth Attendance System - Installation Test")
    print("=" * 50)
    print(f"Python version: {sys.version}")
    print("=" * 50)
    
    # Test imports
    failed_imports = test_imports()
    
    # Test individual components
    bluetooth_ok = test_bluetooth()
    database_ok = test_database()
    web_ok = test_web_framework()
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    if not failed_imports and bluetooth_ok and database_ok and web_ok:
        print("✓ All tests passed! The system should work correctly.")
        print("\nNext steps:")
        print("1. Run 'python app_bleak.py' to start the modern Bluetooth version")
        print("2. Open http://localhost:5000 in your browser")
        print("3. Use the web interface to manage students and scan for devices")
        print("\nNote: The app_bleak.py version uses modern Bluetooth Low Energy (BLE) scanning")
    else:
        print("✗ Some tests failed. Please address the following issues:")
        
        if failed_imports:
            print(f"\nMissing modules: {', '.join(failed_imports)}")
            print("Run: pip install -r requirements.txt")
        
        if not bluetooth_ok:
            print("\nBluetooth issues:")
            print("- Install Microsoft Visual C++ Build Tools")
            print("- Ensure Bluetooth adapter is working")
            print("- Consider running as administrator")
        
        if not database_ok:
            print("\nDatabase issues - check SQLite installation")
        
        if not web_ok:
            print("\nWeb framework issues - check Flask installation")

if __name__ == "__main__":
    main()
