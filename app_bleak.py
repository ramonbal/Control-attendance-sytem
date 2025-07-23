"""
Bluetooth Classroom Attendance System - Using Bleak
Multi-Modal: Bluetooth + Wi-Fi + QR Code + Manual Check-in
Modern comprehensive attendance solution
"""

import time
import threading
import asyncio
import secrets
import socket
import subprocess
import platform
import ipaddress
import pandas as pd
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_socketio import SocketIO, emit
import sqlite3
import json
import qrcode
import io
import base64
from bleak import BleakScanner
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

class MultiModalAttendanceSystem:
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.detected_devices = {}
        self.wifi_devices = {}
        self.loop = None
        self.current_qr_session = None
        self.wifi_scanning = False
        self.wifi_scan_thread = None
        self.current_subject_id = None  # Currently selected subject
        self.init_database()
        
        # Set default subject
        self.set_default_subject()
        
    def init_database(self):
        """Initialize SQLite database with multi-modal support"""
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Create subjects table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_code TEXT UNIQUE NOT NULL,
                subject_name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                student_id TEXT UNIQUE NOT NULL,
                mac_address TEXT UNIQUE,
                wifi_mac_address TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create attendance table with method tracking and subject support
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                subject_id INTEGER,
                session_date DATE NOT NULL,
                first_detected TIMESTAMP,
                last_detected TIMESTAMP,
                method TEXT DEFAULT 'bluetooth',
                status TEXT DEFAULT 'present',
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (student_id) REFERENCES students (student_id),
                FOREIGN KEY (subject_id) REFERENCES subjects (id)
            )
        ''')
        
        # Create sessions table for QR codes with subject support
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS qr_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_code TEXT UNIQUE NOT NULL,
                session_name TEXT NOT NULL,
                subject_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (subject_id) REFERENCES subjects (id)
            )
        ''')
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                subject_id INTEGER,
                session_date DATE NOT NULL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (subject_id) REFERENCES subjects (id)
            )
        ''')
        
        # Add missing columns if they don't exist
        try:
            cursor.execute('ALTER TABLE attendance ADD COLUMN method TEXT DEFAULT "bluetooth"')
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute('ALTER TABLE attendance ADD COLUMN ip_address TEXT')
        except sqlite3.OperationalError:
            pass
            
        try:
            cursor.execute('ALTER TABLE attendance ADD COLUMN user_agent TEXT')
        except sqlite3.OperationalError:
            pass
            
        try:
            cursor.execute('ALTER TABLE students ADD COLUMN wifi_mac_address TEXT')
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e).lower():
                logger.error(f"Error adding wifi_mac_address column: {e}")
        
        try:
            cursor.execute('ALTER TABLE attendance ADD COLUMN subject_id INTEGER')
        except sqlite3.OperationalError:
            pass
            
        try:
            cursor.execute('ALTER TABLE qr_sessions ADD COLUMN subject_id INTEGER')
        except sqlite3.OperationalError:
            pass
            
        try:
            cursor.execute('ALTER TABLE sessions ADD COLUMN subject_id INTEGER')
        except sqlite3.OperationalError:
            pass
        
        # Insert default subject if none exist
        cursor.execute('SELECT COUNT(*) FROM subjects')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO subjects (subject_code, subject_name, description)
                VALUES ('GEN001', 'General Class', 'Default subject for general attendance')
            ''')
        
        conn.commit()
        conn.close()
    
    def set_default_subject(self):
        """Set the first available subject as current"""
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM subjects ORDER BY id LIMIT 1')
        result = cursor.fetchone()
        if result:
            self.current_subject_id = result[0]
        conn.close()
    
    def get_subjects(self):
        """Get all available subjects"""
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, subject_code, subject_name, description FROM subjects ORDER BY subject_name')
        results = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries for template compatibility
        subjects = []
        for row in results:
            subjects.append({
                'id': row[0],
                'subject_code': row[1],
                'subject_name': row[2],
                'description': row[3]
            })
        return subjects
    
    def add_subject(self, subject_code, subject_name, description=""):
        """Add a new subject"""
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO subjects (subject_code, subject_name, description)
                VALUES (?, ?, ?)
            ''', (subject_code, subject_name, description))
            conn.commit()
            subject_id = cursor.lastrowid
            conn.close()
            return subject_id
        except sqlite3.IntegrityError:
            conn.close()
            raise Exception('Subject code already exists')
    
    def delete_subject(self, subject_id):
        """Delete a subject and all its related attendance records"""
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Check if there are other subjects available
        cursor.execute('SELECT COUNT(*) FROM subjects')
        total_subjects = cursor.fetchone()[0]
        
        if total_subjects <= 1:
            conn.close()
            raise Exception('Cannot delete the last subject. At least one subject must exist.')
        
        # Check if this is the current subject
        if self.current_subject_id == subject_id:
            # Find another subject to set as current
            cursor.execute('SELECT id FROM subjects WHERE id != ? ORDER BY id LIMIT 1', (subject_id,))
            alternative = cursor.fetchone()
            if alternative:
                self.current_subject_id = alternative[0]
                logger.info(f"Current subject automatically changed to ID: {alternative[0]}")
            else:
                self.current_subject_id = None
        
        # Delete attendance records for this subject
        cursor.execute('DELETE FROM attendance WHERE subject_id = ?', (subject_id,))
        
        # Delete QR sessions for this subject
        cursor.execute('DELETE FROM qr_sessions WHERE subject_id = ?', (subject_id,))
        
        # Delete the subject
        cursor.execute('DELETE FROM subjects WHERE id = ?', (subject_id,))
        
        conn.commit()
        conn.close()
        
        return True
    
    def set_current_subject(self, subject_id):
        """Set the current subject for attendance tracking"""
        # Verify subject exists
        subject = self.get_subject_by_id(subject_id)
        if subject:
            self.current_subject_id = subject_id
            logger.info(f"Current subject set to: {subject['subject_name']} (ID: {subject_id})")
            return True
        return False
    
    def get_subject_by_id(self, subject_id):
        """Get subject details by ID"""
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, subject_code, subject_name FROM subjects WHERE id = ?', (subject_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'subject_code': result[1],
                'subject_name': result[2]
            }
        return None
        
    def get_current_subject(self):
        """Get current subject information"""
        if not self.current_subject_id:
            return None
        
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, subject_code, subject_name, description FROM subjects WHERE id = ?', 
                      (self.current_subject_id,))
        subject = cursor.fetchone()
        conn.close()
        return subject
    
    async def scan_bluetooth_devices_async(self):
        """Asynchronously scan for Bluetooth devices using Bleak"""
        logger.info("Starting Bluetooth LE scan...")
        
        while self.scanning:
            try:
                # Discover BLE devices with advertisement data to get RSSI
                # Use a longer timeout and different scanning parameters for better detection
                devices = await BleakScanner.discover(
                    timeout=10.0, 
                    return_adv=True,
                    scanning_mode="active"  # More aggressive scanning
                )
                current_time = datetime.now()
                
                logger.info(f"Found {len(devices)} BLE devices")
                
                # Use a set to track processed devices in this scan to avoid duplicates
                processed_in_scan = set()
                
                for device_addr, (device, advertisement_data) in devices.items():
                    # Process device (address is the MAC address)
                    if device.address:
                        # Normalize MAC for duplicate checking (use device.address, not device_addr)
                        normalized_mac = device.address.upper().replace('-', ':')
                        
                        # Skip if already processed in this scan
                        if normalized_mac in processed_in_scan:
                            logger.debug(f"Skipping duplicate in same scan: {normalized_mac}")
                            continue
                        
                        processed_in_scan.add(normalized_mac)
                        
                        device_name = device.name if device.name else f"Unknown Device ({normalized_mac})"
                        
                        # Get RSSI from advertisement data
                        rssi = advertisement_data.rssi if advertisement_data else None
                        
                        logger.debug(f"Found device: {normalized_mac} - {device_name} (RSSI: {rssi})")
                        
                        self.process_detected_device(
                            normalized_mac,  # Use normalized MAC consistently
                            device_name, 
                            current_time,
                            rssi
                        )
                
                # Emit update to web interface
                devices_info = self.get_detected_devices_info()
                logger.info(f"Emitting {len(devices_info)} devices to web interface")
                socketio.emit('device_update', {
                    'devices': devices_info,
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S')
                })
                
                await asyncio.sleep(15)  # Reduced from 30 to 15 seconds between scans
                
            except Exception as e:
                logger.error(f"Bluetooth scan error: {e}")
                await asyncio.sleep(10)
    
    def scan_bluetooth_devices_sync(self):
        """Synchronous wrapper for async Bluetooth scanning"""
        # Create new event loop for this thread
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            self.loop.run_until_complete(self.scan_bluetooth_devices_async())
        except Exception as e:
            logger.error(f"Error in sync scan wrapper: {e}")
        finally:
            try:
                # Cancel all pending tasks
                pending = asyncio.all_tasks(self.loop)
                for task in pending:
                    task.cancel()
                # Wait for tasks to be cancelled
                if pending:
                    self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            finally:
                if self.loop:
                    self.loop.close()
                self.loop = None
    
    def process_detected_device(self, mac_address, device_name, detection_time, rssi=None):
        """Process a detected Bluetooth device"""
        # Skip processing if no current subject is set
        if not self.current_subject_id:
            logger.debug("No current subject selected. Skipping attendance tracking.")
            return
            
        # Normalize MAC address format (should already be normalized from caller)
        mac_address = mac_address.upper().replace('-', ':')
        
        # Check if this is a duplicate detection within a short time frame
        if mac_address in self.detected_devices:
            time_since_last = (detection_time - self.detected_devices[mac_address]['last_seen']).total_seconds()
            if time_since_last < 5:  # Less than 5 seconds since last detection
                logger.debug(f"Skipping duplicate detection of {mac_address} (last seen {time_since_last:.1f}s ago)")
                # Just update the last seen time and RSSI if it's newer
                self.detected_devices[mac_address]['last_seen'] = detection_time
                if rssi is not None:
                    self.detected_devices[mac_address]['rssi'] = rssi
                return
        
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Check if this MAC address belongs to a registered student
        cursor.execute('SELECT student_id, name FROM students WHERE mac_address = ?', (mac_address,))
        student = cursor.fetchone()
        
        if student:
            student_id, student_name = student
            today = detection_time.date()
            
            logger.info(f"Detected registered student: {student_name} ({mac_address})")
            
            # Check if attendance record exists for today and this subject
            cursor.execute('''
                SELECT id, first_detected FROM attendance 
                WHERE student_id = ? AND session_date = ? AND subject_id = ?
            ''', (student_id, today, self.current_subject_id))
            
            existing_record = cursor.fetchone()
            
            if existing_record:
                # Update attendance record
                cursor.execute('''
                    UPDATE attendance 
                    SET last_detected = ?, method = ? 
                    WHERE student_id = ? AND session_date = ? AND subject_id = ?
                ''', (detection_time, 'bluetooth', student_id, today, self.current_subject_id))
            else:
                # Create new attendance record
                cursor.execute('''
                    INSERT INTO attendance (student_id, subject_id, session_date, first_detected, last_detected, method)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (student_id, self.current_subject_id, today, detection_time, detection_time, 'bluetooth'))
            
            # Update detected devices cache
            self.detected_devices[mac_address] = {
                'student_id': student_id,
                'student_name': student_name,
                'device_name': device_name,
                'last_seen': detection_time,
                'mac_address': mac_address,
                'rssi': rssi,
                'registered': True
            }
        else:
            # Log unregistered devices for potential registration
            logger.info(f"Detected unregistered device: {device_name} ({mac_address})")
            
            # Also store unregistered devices in cache for display
            self.detected_devices[mac_address] = {
                'student_id': None,
                'student_name': None,
                'device_name': device_name,
                'last_seen': detection_time,
                'mac_address': mac_address,
                'rssi': rssi,
                'registered': False
            }
        
        conn.commit()
        conn.close()
    
    def get_detected_devices_info(self):
        """Get information about currently detected devices"""
        current_time = datetime.now()
        active_devices = {}
        
        logger.info(f"Filtering devices: have {len(self.detected_devices)} total devices")
        
        # Clean up old devices from cache (older than 10 minutes)
        devices_to_remove = []
        for mac, info in self.detected_devices.items():
            time_diff = (current_time - info['last_seen']).total_seconds()
            if time_diff > 600:  # 10 minutes
                devices_to_remove.append(mac)
        
        for mac in devices_to_remove:
            logger.debug(f"Removing old device from cache: {mac}")
            del self.detected_devices[mac]
        
        if devices_to_remove:
            logger.info(f"Cleaned up {len(devices_to_remove)} old devices from cache")
        
        # Only show devices detected in the last 10 minutes (increased from 5)
        for mac, info in self.detected_devices.items():
            time_diff = (current_time - info['last_seen']).total_seconds()
            if time_diff < 600:  # 10 minutes (increased window)
                active_devices[mac] = info.copy()
                active_devices[mac]['last_seen'] = info['last_seen'].strftime('%H:%M:%S')
                logger.info(f"Device {mac} included (age: {time_diff:.1f}s)")
            else:
                logger.info(f"Device {mac} filtered out (age: {time_diff:.1f}s)")
        
        # Sort devices: First by RSSI (strongest signal first), then by device name
        def sort_key(item):
            mac, device = item
            # Get RSSI value for sorting (higher RSSI = stronger signal = better)
            rssi = device.get('rssi')
            if rssi is None or rssi == 'None':
                rssi = -999  # Put devices with no RSSI at the end
            else:
                try:
                    rssi = int(rssi)
                except (ValueError, TypeError):
                    rssi = -999
            
            # Get device name for secondary sorting
            device_name = device.get('device_name', 'Unknown Device')
            
            # Return tuple: (-rssi, device_name) - negative RSSI for descending order
            return (-rssi, device_name.lower())
        
        # Convert to sorted list of tuples, then back to ordered dict
        sorted_devices = dict(sorted(active_devices.items(), key=sort_key))
        
        logger.info(f"Returning {len(sorted_devices)} active devices (sorted by signal strength)")
        return sorted_devices
    
    def start_scanning(self):
        """Start Bluetooth scanning in a separate thread"""
        if not self.scanning:
            self.scanning = True
            # Always create a new thread to avoid issues with stopped threads
            self.scan_thread = threading.Thread(target=self.scan_bluetooth_devices_sync)
            self.scan_thread.daemon = True
            self.scan_thread.start()
            logger.info("Bluetooth scanning started")
            
            # Perform a quick initial scan in a separate thread to populate dashboard faster
            threading.Thread(target=self._quick_initial_scan, daemon=True).start()
            
            return True
        return False
    
    def _quick_initial_scan(self):
        """Perform a quick 5-second scan to populate dashboard immediately"""
        try:
            # Create a temporary event loop for this quick scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def quick_scan():
                logger.info("Performing quick initial scan...")
                devices = await BleakScanner.discover(
                    timeout=5.0, 
                    return_adv=True,
                    scanning_mode="active"  # More aggressive scanning
                )
                current_time = datetime.now()
                
                logger.info(f"Quick scan found {len(devices)} BLE devices")
                
                for device_addr, (device, advertisement_data) in devices.items():
                    if device.address:
                        # Normalize MAC address consistently
                        normalized_mac = device.address.upper().replace('-', ':')
                        device_name = device.name if device.name else f"Unknown Device ({normalized_mac})"
                        rssi = advertisement_data.rssi if advertisement_data else None
                        
                        self.process_detected_device(
                            normalized_mac, 
                            device_name, 
                            current_time,
                            rssi
                        )
                
                # Emit quick update to web interface
                devices_info = self.get_detected_devices_info()
                logger.info(f"Quick scan emitting {len(devices_info)} devices to web interface")
                socketio.emit('device_update', {
                    'devices': devices_info,
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            loop.run_until_complete(quick_scan())
            loop.close()
            
        except Exception as e:
            logger.error(f"Quick initial scan error: {e}")
    
    def stop_scanning(self):
        """Stop Bluetooth scanning"""
        if self.scanning:
            self.scanning = False
            if self.scan_thread and self.scan_thread.is_alive():
                # Wait for thread to finish gracefully
                self.scan_thread.join(timeout=5)
            # Reset the loop reference
            self.loop = None
            logger.info("Bluetooth scanning stopped")
            return True
        return False
    
    # Wi-Fi Network Scanning Methods
    def get_local_network_range(self):
        """Get the local network IP range for scanning"""
        try:
            # Get local IP address
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Create network object
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network.network_address), str(network.broadcast_address)
        except Exception as e:
            logger.error(f"Error getting network range: {e}")
            return "192.168.1.1", "192.168.1.254"
    
    def scan_wifi_devices_async(self):
        """Scan for devices on the local Wi-Fi network"""
        logger.info("Starting Wi-Fi network scan...")
        
        while self.wifi_scanning:
            try:
                current_time = datetime.now()
                network_start, network_end = self.get_local_network_range()
                
                # Get ARP table (devices that have communicated recently)
                wifi_devices = self.get_arp_table()
                
                logger.info(f"Found {len(wifi_devices)} Wi-Fi devices")
                
                for device_info in wifi_devices:
                    mac_address = device_info.get('mac', '').upper().replace('-', ':')
                    ip_address = device_info.get('ip', '')
                    device_name = device_info.get('hostname', f"Wi-Fi Device ({ip_address})")
                    
                    if mac_address and ip_address:
                        self.process_wifi_device(mac_address, device_name, ip_address, current_time)
                
                # Emit Wi-Fi update to web interface
                wifi_info = self.get_wifi_devices_info()
                logger.info(f"Emitting {len(wifi_info)} Wi-Fi devices to web interface")
                socketio.emit('wifi_device_update', {
                    'devices': wifi_info,
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S')
                })
                
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                logger.error(f"Wi-Fi scan error: {e}")
                time.sleep(15)
    
    def get_arp_table(self):
        """Get ARP table to find devices on local network"""
        devices = []
        try:
            if platform.system() == "Windows":
                # Use arp command on Windows
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '---' in line or not line.strip():
                            continue
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip = parts[0].strip()
                            mac = parts[1].strip().upper().replace('-', ':')
                            if self.is_valid_mac(mac) and self.is_valid_ip(ip):
                                devices.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'hostname': self.get_hostname_from_ip(ip)
                                })
            else:
                # Use arp command on Linux/Mac
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        # Parse arp output format
                        if '(' in line and ')' in line and 'at' in line:
                            parts = line.split()
                            ip = parts[1].strip('()')
                            mac = parts[3].strip().upper().replace('-', ':')
                            hostname = parts[0] if parts[0] != '?' else f"Device-{ip}"
                            if self.is_valid_mac(mac) and self.is_valid_ip(ip):
                                devices.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'hostname': hostname
                                })
                                
        except subprocess.TimeoutExpired:
            logger.warning("ARP command timed out")
        except Exception as e:
            logger.error(f"Error getting ARP table: {e}")
        
        return devices
    
    def is_valid_mac(self, mac):
        """Validate MAC address format"""
        try:
            parts = mac.split(':')
            return len(parts) == 6 and all(len(part) == 2 for part in parts)
        except:
            return False
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except:
            return False
    
    def get_hostname_from_ip(self, ip):
        """Try to get hostname from IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return f"Device-{ip}"
    
    def process_wifi_device(self, mac_address, device_name, ip_address, detection_time):
        """Process a detected Wi-Fi device"""
        # Skip processing if no current subject is set
        if not self.current_subject_id:
            logger.debug("No current subject selected. Skipping Wi-Fi attendance tracking.")
            return
            
        # Normalize MAC address format
        mac_address = mac_address.upper().replace('-', ':')
        
        # Check if this is a duplicate detection within a short time frame
        if mac_address in self.wifi_devices:
            time_since_last = (detection_time - self.wifi_devices[mac_address]['last_seen']).total_seconds()
            if time_since_last < 30:  # Less than 30 seconds since last detection
                logger.debug(f"Skipping duplicate Wi-Fi detection of {mac_address} (last seen {time_since_last:.1f}s ago)")
                # Just update the last seen time
                self.wifi_devices[mac_address]['last_seen'] = detection_time
                self.wifi_devices[mac_address]['ip_address'] = ip_address
                return
        
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Check if this MAC address belongs to a registered student (Wi-Fi MAC)
        cursor.execute('SELECT student_id, name FROM students WHERE wifi_mac_address = ?', (mac_address,))
        student = cursor.fetchone()
        
        if student:
            student_id, student_name = student
            today = detection_time.date()
            
            logger.info(f"Detected registered student via Wi-Fi: {student_name} ({mac_address})")
            
            # Check if attendance record exists for today and this subject
            cursor.execute('''
                SELECT id, first_detected FROM attendance 
                WHERE student_id = ? AND session_date = ? AND subject_id = ?
            ''', (student_id, today, self.current_subject_id))
            
            existing_record = cursor.fetchone()
            
            if existing_record:
                # Update attendance record
                cursor.execute('''
                    UPDATE attendance 
                    SET last_detected = ?, method = ?, ip_address = ?
                    WHERE student_id = ? AND session_date = ? AND subject_id = ?
                ''', (detection_time, 'wifi', ip_address, student_id, today, self.current_subject_id))
            else:
                # Create new attendance record
                cursor.execute('''
                    INSERT INTO attendance (student_id, subject_id, session_date, first_detected, last_detected, method, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (student_id, self.current_subject_id, today, detection_time, detection_time, 'wifi', ip_address))
            
            # Update Wi-Fi devices cache
            self.wifi_devices[mac_address] = {
                'student_id': student_id,
                'student_name': student_name,
                'device_name': device_name,
                'last_seen': detection_time,
                'mac_address': mac_address,
                'ip_address': ip_address,
                'registered': True
            }
        else:
            # Log unregistered Wi-Fi devices for potential registration
            logger.info(f"Detected unregistered Wi-Fi device: {device_name} ({mac_address}) at {ip_address}")
            
            # Also store unregistered devices in cache for display
            self.wifi_devices[mac_address] = {
                'student_id': None,
                'student_name': None,
                'device_name': device_name,
                'last_seen': detection_time,
                'mac_address': mac_address,
                'ip_address': ip_address,
                'registered': False
            }
        
        conn.commit()
        conn.close()
    
    def get_wifi_devices_info(self):
        """Get information about currently detected Wi-Fi devices"""
        current_time = datetime.now()
        active_devices = {}
        
        logger.info(f"Filtering Wi-Fi devices: have {len(self.wifi_devices)} total devices")
        
        # Clean up old devices from cache (older than 20 minutes)
        devices_to_remove = []
        for mac, info in self.wifi_devices.items():
            time_diff = (current_time - info['last_seen']).total_seconds()
            if time_diff > 1200:  # 20 minutes
                devices_to_remove.append(mac)
        
        for mac in devices_to_remove:
            logger.debug(f"Removing old Wi-Fi device from cache: {mac}")
            del self.wifi_devices[mac]
        
        if devices_to_remove:
            logger.info(f"Cleaned up {len(devices_to_remove)} old Wi-Fi devices from cache")
        
        # Only show devices detected in the last 20 minutes
        for mac, info in self.wifi_devices.items():
            time_diff = (current_time - info['last_seen']).total_seconds()
            if time_diff < 1200:  # 20 minutes
                active_devices[mac] = info.copy()
                active_devices[mac]['last_seen'] = info['last_seen'].strftime('%H:%M:%S')
                logger.info(f"Wi-Fi Device {mac} included (age: {time_diff:.1f}s)")
            else:
                logger.info(f"Wi-Fi Device {mac} filtered out (age: {time_diff:.1f}s)")
        
        # Sort devices by device name
        sorted_devices = dict(sorted(active_devices.items(), key=lambda x: x[1].get('device_name', 'Unknown').lower()))
        
        logger.info(f"Returning {len(sorted_devices)} active Wi-Fi devices")
        return sorted_devices
    
    def start_wifi_scanning(self):
        """Start Wi-Fi scanning in a separate thread"""
        if not self.wifi_scanning:
            self.wifi_scanning = True
            self.wifi_scan_thread = threading.Thread(target=self.scan_wifi_devices_async)
            self.wifi_scan_thread.daemon = True
            self.wifi_scan_thread.start()
            logger.info("Wi-Fi scanning started")
            return True
        return False
    
    def stop_wifi_scanning(self):
        """Stop Wi-Fi scanning"""
        if self.wifi_scanning:
            self.wifi_scanning = False
            if self.wifi_scan_thread and self.wifi_scan_thread.is_alive():
                # Wait for thread to finish gracefully
                self.wifi_scan_thread.join(timeout=5)
            logger.info("Wi-Fi scanning stopped")
            return True
        return False
    
    # QR Code Attendance Methods
    def create_qr_session(self, session_name, duration_minutes=60):
        """Create a new QR code session"""
        session_code = secrets.token_urlsafe(8)
        expires_at = datetime.now() + timedelta(minutes=duration_minutes)
        
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Deactivate previous sessions
        cursor.execute('UPDATE qr_sessions SET active = 0')
        
        # Create new session
        cursor.execute('''
            INSERT INTO qr_sessions (session_code, session_name, expires_at)
            VALUES (?, ?, ?)
        ''', (session_code, session_name, expires_at))
        
        conn.commit()
        conn.close()
        
        self.current_qr_session = {
            'code': session_code,
            'name': session_name,
            'expires': expires_at
        }
        
        return session_code
    
    def generate_qr_code(self, session_code):
        """Generate QR code for attendance"""
        # Get the actual network IP address instead of localhost
        try:
            # Get local IP address that's accessible from other devices
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            # Alternative method if the above doesn't work well
            if local_ip.startswith('127.') or local_ip == '::1':
                # Try connecting to a remote address to find local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
        except Exception as e:
            logger.warning(f"Could not determine local IP: {e}, falling back to localhost")
            local_ip = "localhost"
        
        check_in_url = f"http://{local_ip}:5001/qr_checkin/{session_code}"
        logger.info(f"Generated QR code URL: {check_in_url}")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(check_in_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return img_str
    
    def qr_check_in(self, session_code, student_id, ip_address=None, user_agent=None):
        """Process QR code check-in"""
        # Check if current subject is set
        if not self.current_subject_id:
            return {'success': False, 'message': 'No current subject selected. Please ask your teacher to select a subject first.'}
            
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Verify session
        cursor.execute('''
            SELECT id, expires_at, session_name FROM qr_sessions 
            WHERE session_code = ? AND active = 1
        ''', (session_code,))
        
        session = cursor.fetchone()
        if not session:
            conn.close()
            return {'success': False, 'message': 'Invalid or expired session'}
        
        expires_at = datetime.fromisoformat(session[1])
        if datetime.now() > expires_at:
            conn.close()
            return {'success': False, 'message': 'Session has expired'}
        
        # Check if student exists
        cursor.execute('SELECT name FROM students WHERE student_id = ?', (student_id,))
        student = cursor.fetchone()
        if not student:
            conn.close()
            return {'success': False, 'message': 'Student ID not found'}
        
        # Record attendance
        today = datetime.now().date()
        current_time = datetime.now()
        
        # Check if already has attendance today for this subject
        cursor.execute('''
            SELECT id, method FROM attendance 
            WHERE student_id = ? AND session_date = ? AND subject_id = ?
        ''', (student_id, today, self.current_subject_id))
        
        existing = cursor.fetchone()
        
        if existing:
            # Update existing record
            cursor.execute('''
                UPDATE attendance 
                SET last_detected = ?, method = ?, ip_address = ?, user_agent = ?
                WHERE student_id = ? AND session_date = ? AND subject_id = ?
            ''', (current_time, 'qr_code', ip_address, user_agent, student_id, today, self.current_subject_id))
            message = f"Welcome back, {student[0]}! (Updated via QR)"
        else:
            # Create new record
            cursor.execute('''
                INSERT INTO attendance (student_id, subject_id, session_date, first_detected, last_detected, method, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (student_id, self.current_subject_id, today, current_time, current_time, 'qr_code', ip_address, user_agent))
            message = f"Welcome, {student[0]}! (Checked in via QR)"
        
        conn.commit()
        conn.close()
        
        return {'success': True, 'message': message, 'student_name': student[0]}
    
    def manual_check_in(self, student_id, method="manual"):
        """Manual student check-in"""
        # Check if current subject is set
        if not self.current_subject_id:
            return {'success': False, 'message': 'No current subject selected. Please select a subject first.'}
            
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Check if student exists
        cursor.execute('SELECT name FROM students WHERE student_id = ?', (student_id,))
        student = cursor.fetchone()
        if not student:
            conn.close()
            return {'success': False, 'message': 'Student not found'}
        
        today = datetime.now().date()
        current_time = datetime.now()
        
        # Check existing attendance for this subject
        cursor.execute('''
            SELECT id FROM attendance 
            WHERE student_id = ? AND session_date = ? AND subject_id = ?
        ''', (student_id, today, self.current_subject_id))
        
        existing = cursor.fetchone()
        
        if existing:
            # Update existing
            cursor.execute('''
                UPDATE attendance 
                SET last_detected = ?, method = ?
                WHERE student_id = ? AND session_date = ? AND subject_id = ?
            ''', (current_time, method, student_id, today, self.current_subject_id))
            message = f"{student[0]} attendance updated (Manual)"
        else:
            # Create new
            cursor.execute('''
                INSERT INTO attendance (student_id, subject_id, session_date, first_detected, last_detected, method)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (student_id, self.current_subject_id, today, current_time, current_time, method))
            message = f"{student[0]} checked in successfully (Manual)"
        
        conn.commit()
        conn.close()
        
        return {'success': True, 'message': message}
    
    def get_attendance_summary(self, date=None, subject_id=None):
        """Get comprehensive attendance summary"""
        if not date:
            date = datetime.now().date()
        
        if subject_id is None:
            subject_id = self.current_subject_id
        
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.name, s.student_id, s.mac_address,
                   a.first_detected, a.last_detected, a.method, a.status,
                   sub.subject_name
            FROM students s
            LEFT JOIN attendance a ON s.student_id = a.student_id 
                AND a.session_date = ? AND a.subject_id = ?
            LEFT JOIN subjects sub ON a.subject_id = sub.id
            ORDER BY s.name
        ''', (date, subject_id))
        
        records = cursor.fetchall()
        conn.close()
        
        return records
    
    def import_students_from_excel(self, excel_file_path):
        """Import students from Excel file with ID and Name columns"""
        try:
            # Read Excel file
            df = pd.read_excel(excel_file_path)
            
            # Normalize column names (handle different cases and spaces)
            df.columns = df.columns.str.strip().str.lower()
            
            # Look for ID and Name columns with various possible names
            id_col = None
            name_col = None
            
            for col in df.columns:
                if col in ['id', 'student_id', 'studentid', 'student id']:
                    id_col = col
                elif col in ['name', 'student_name', 'studentname', 'student name', 'full_name', 'fullname']:
                    name_col = col
            
            if id_col is None or name_col is None:
                return {
                    'success': False, 
                    'message': f'Required columns not found. Found columns: {list(df.columns)}. Need ID and Name columns.',
                    'imported': 0,
                    'errors': []
                }
            
            conn = sqlite3.connect('attendance.db')
            cursor = conn.cursor()
            
            imported_count = 0
            errors = []
            
            for index, row in df.iterrows():
                try:
                    student_id = str(row[id_col]).strip()
                    name = str(row[name_col]).strip()
                    
                    # Skip empty rows
                    if pd.isna(row[id_col]) or pd.isna(row[name_col]) or not student_id or not name:
                        continue
                    
                    # Insert student into database
                    cursor.execute('''
                        INSERT INTO students (name, student_id, mac_address, wifi_mac_address)
                        VALUES (?, ?, NULL, NULL)
                    ''', (name, student_id))
                    
                    imported_count += 1
                    
                except sqlite3.IntegrityError as e:
                    if "UNIQUE constraint failed" in str(e):
                        errors.append(f"Row {index + 2}: Student ID '{student_id}' already exists")
                    else:
                        errors.append(f"Row {index + 2}: Database error - {str(e)}")
                except Exception as e:
                    errors.append(f"Row {index + 2}: Error processing - {str(e)}")
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'message': f'Successfully imported {imported_count} students',
                'imported': imported_count,
                'errors': errors
            }
            
        except FileNotFoundError:
            return {
                'success': False,
                'message': f'Excel file not found: {excel_file_path}',
                'imported': 0,
                'errors': []
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Error reading Excel file: {str(e)}',
                'imported': 0,
                'errors': []
            }

# Initialize the system
attendance_system = MultiModalAttendanceSystem()

@app.route('/')
def index():
    """Main dashboard"""
    response = make_response(render_template('dashboard.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/students')
def students():
    """Student management page"""
    conn = sqlite3.connect('attendance.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM students ORDER BY name')
    students_list = cursor.fetchall()
    conn.close()
    
    return render_template('students.html', students=students_list)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    """Add new student"""
    if request.method == 'POST':
        name = request.form['name']
        student_id = request.form['student_id']
        mac_address = request.form.get('mac_address', '').upper().replace('-', ':') if request.form.get('mac_address') else None
        wifi_mac_address = request.form.get('wifi_mac_address', '').upper().replace('-', ':') if request.form.get('wifi_mac_address') else None
        
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO students (name, student_id, mac_address, wifi_mac_address)
                VALUES (?, ?, ?, ?)
            ''', (name, student_id, mac_address, wifi_mac_address))
            conn.commit()
            conn.close()
            return redirect(url_for('students'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('add_student.html', error='Student ID or MAC address already exists')
    
    return render_template('add_student.html')

@app.route('/import_students', methods=['GET', 'POST'])
def import_students():
    """Import students from Excel file"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'excel_file' not in request.files:
            return render_template('import_students.html', error='No file selected')
        
        file = request.files['excel_file']
        if file.filename == '':
            return render_template('import_students.html', error='No file selected')
        
        if file and file.filename.lower().endswith(('.xlsx', '.xls')):
            # Save uploaded file temporarily
            filename = f"temp_students_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            filepath = os.path.join(os.getcwd(), filename)
            file.save(filepath)
            
            try:
                # Import students from Excel
                result = attendance_system.import_students_from_excel(filepath)
                
                # Clean up temporary file
                os.remove(filepath)
                
                return render_template('import_students.html', result=result)
                
            except Exception as e:
                # Clean up temporary file if error occurs
                if os.path.exists(filepath):
                    os.remove(filepath)
                return render_template('import_students.html', error=f'Error processing file: {str(e)}')
        else:
            return render_template('import_students.html', error='Please upload an Excel file (.xlsx or .xls)')
    
    return render_template('import_students.html')

@app.route('/clear_all_students', methods=['POST'])
def clear_all_students():
    """Clear all students from database (for testing)"""
    conn = sqlite3.connect('attendance.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM students')
    cursor.execute('DELETE FROM attendance')
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'All students and attendance records cleared'})

@app.route('/attendance')
def attendance():
    """View comprehensive attendance records"""
    date = request.args.get('date', datetime.now().date())
    records = attendance_system.get_attendance_summary(date)
    return render_template('attendance.html', records=records, date=date)

# QR Code Routes
@app.route('/qr_attendance')
def qr_attendance_page():
    """QR Code attendance management"""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M')
    return render_template('qr_attendance.html', current_time=current_time)

# Wi-Fi Attendance Routes
@app.route('/wifi_attendance')
def wifi_attendance_page():
    """Wi-Fi attendance scanner page"""
    return render_template('wifi_attendance.html')

@app.route('/create_qr_session', methods=['POST'])
def create_qr_session():
    """Create new QR attendance session"""
    session_name = request.form.get('session_name', f'Class {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    duration = int(request.form.get('duration', 60))
    
    session_code = attendance_system.create_qr_session(session_name, duration)
    qr_image = attendance_system.generate_qr_code(session_code)
    
    return render_template('qr_session.html', 
                         session_code=session_code,
                         qr_image=qr_image,
                         session_name=session_name,
                         duration=duration)

@app.route('/qr_checkin/<session_code>')
def qr_checkin_form(session_code):
    """Student QR check-in form"""
    return render_template('qr_checkin.html', session_code=session_code)

@app.route('/qr_checkin/<session_code>', methods=['POST'])
def process_qr_checkin(session_code):
    """Process QR check-in"""
    student_id = request.form.get('student_id')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    result = attendance_system.qr_check_in(session_code, student_id, ip_address, user_agent)
    return render_template('checkin_result.html', result=result)

# Subject Management Routes
@app.route('/subjects')
def subjects_page():
    """Subject management page"""
    subjects = attendance_system.get_subjects()
    current_subject = None
    if attendance_system.current_subject_id:
        current_subject = attendance_system.get_subject_by_id(attendance_system.current_subject_id)
    
    # Debug output
    logger.info(f"DEBUG: subjects_page - subjects count: {len(subjects)}")
    for i, subject in enumerate(subjects):
        logger.info(f"DEBUG: Subject {i+1}: {subject} (id type: {type(subject.get('id'))})")
    logger.info(f"DEBUG: current_subject_id: {attendance_system.current_subject_id}")
    logger.info(f"DEBUG: current_subject: {current_subject}")
    
    # Debug data before rendering
    logger.info(f"DEBUG subjects_page: Found {len(subjects)} subjects")
    for i, subject in enumerate(subjects):
        logger.info(f"DEBUG subject {i}: {subject}")
    
    # Check if debug mode requested
    debug_param = request.args.get('debug')
    logger.info(f"DEBUG: request.args = {dict(request.args)}")
    logger.info(f"DEBUG: debug_param = '{debug_param}', type = {type(debug_param)}")
    
    # Force debug response for testing
    if 'debug' in request.args:
        logger.info("DEBUG: Forcing JSON response")
        return jsonify({
            'subjects': subjects,
            'current_subject': current_subject,
            'subjects_count': len(subjects),
            'first_subject': subjects[0] if subjects else None,
            'debug_test': 'working'
        })
    else:
        logger.info(f"DEBUG: Rendering template, request.args = {dict(request.args)}")
    
    return render_template('subjects.html', subjects=subjects, current_subject=current_subject)

@app.route('/test_subjects_debug')
def test_subjects_debug():
    """Test route to debug subject template rendering"""
    subjects = attendance_system.get_subjects()
    logger.info(f"TEST: About to render template with subjects: {subjects}")
    return render_template('test_subjects.html', subjects=subjects)

@app.route('/api/debug_subjects', methods=['GET'])
def debug_subjects():
    """Debug endpoint to check subject data"""
    subjects = attendance_system.get_subjects()
    return {
        'count': len(subjects),
        'subjects': subjects,
        'first_subject': subjects[0] if subjects else None
    }

@app.route('/api/add_subject', methods=['POST'])
def add_subject():
    """Add a new subject"""
    subject_code = request.form.get('subject_code')
    subject_name = request.form.get('subject_name')
    description = request.form.get('description', '')
    
    if not subject_code or not subject_name:
        return jsonify({'success': False, 'message': 'Subject code and name are required'})
    
    try:
        subject_id = attendance_system.add_subject(subject_code, subject_name, description)
        return jsonify({'success': True, 'message': f'Subject "{subject_name}" added successfully', 'subject_id': subject_id})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/delete_subject', methods=['POST'])
def delete_subject():
    """Delete a subject"""
    data = request.get_json()
    subject_id = data.get('subject_id')
    
    if not subject_id:
        return jsonify({'success': False, 'message': 'Subject ID is required'})
    
    try:
        # Get subject name before deletion for the success message
        subject = attendance_system.get_subject_by_id(subject_id)
        if not subject:
            return jsonify({'success': False, 'message': 'Subject not found'})
        
        success = attendance_system.delete_subject(subject_id)
        if success:
            return jsonify({'success': True, 'message': f'Subject "{subject["subject_name"]}" deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete subject'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/set_current_subject', methods=['POST'])
def set_current_subject():
    """Set the current subject for attendance tracking"""
    data = request.get_json()
    subject_id = data.get('subject_id')
    
    if not subject_id:
        return jsonify({'success': False, 'message': 'Subject ID is required'})
    
    try:
        success = attendance_system.set_current_subject(subject_id)
        if success:
            subject = attendance_system.get_subject_by_id(subject_id)
            return jsonify({'success': True, 'message': f'Current subject set to "{subject["subject_name"]}"'})
        else:
            return jsonify({'success': False, 'message': 'Subject not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Manual Check-in Routes
@app.route('/manual_attendance')
def manual_attendance_page():
    """Manual attendance page"""
    conn = sqlite3.connect('attendance.db')
    cursor = conn.cursor()
    cursor.execute('SELECT student_id, name FROM students ORDER BY name')
    students = cursor.fetchall()
    conn.close()
    
    return render_template('manual_attendance.html', students=students)

@app.route('/manual_checkin', methods=['POST'])
def manual_checkin():
    """Process manual check-in"""
    student_id = request.form.get('student_id')
    result = attendance_system.manual_check_in(student_id)
    return jsonify(result)

# Multi-modal Dashboard
@app.route('/dashboard')
def multi_dashboard():
    """Comprehensive multi-modal dashboard"""
    # Get subject_id from query parameter if provided
    subject_id = request.args.get('subject_id')
    if subject_id:
        subject_id = int(subject_id)
    
    records = attendance_system.get_attendance_summary(subject_id=subject_id)
    devices_info = attendance_system.get_detected_devices_info()
    wifi_info = attendance_system.get_wifi_devices_info()
    
    current_subject = None
    if attendance_system.current_subject_id:
        current_subject = attendance_system.get_subject_by_id(attendance_system.current_subject_id)
    
    subjects = attendance_system.get_subjects()
    
    return render_template('multi_dashboard.html', 
                         records=records, 
                         devices=devices_info,
                         wifi_devices=wifi_info,
                         current_qr=attendance_system.current_qr_session,
                         current_subject=current_subject,
                         subjects=subjects)

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """API endpoint to start Bluetooth scanning"""
    success = attendance_system.start_scanning()
    return jsonify({'success': success, 'message': 'Scanning started' if success else 'Already scanning'})

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    """API endpoint to stop Bluetooth scanning"""
    success = attendance_system.stop_scanning()
    return jsonify({'success': success, 'message': 'Scanning stopped'})

@app.route('/api/detected_devices')
def get_detected_devices():
    """API endpoint to get currently detected devices"""
    return jsonify(attendance_system.get_detected_devices_info())

@app.route('/api/scan_status')
def get_scan_status():
    """API endpoint to get current scanning status"""
    return jsonify({
        'scanning': attendance_system.scanning,
        'thread_alive': attendance_system.scan_thread.is_alive() if attendance_system.scan_thread else False
    })

# Wi-Fi Scanning Routes
@app.route('/api/start_wifi_scan', methods=['POST'])
def start_wifi_scan():
    """API endpoint to start Wi-Fi scanning"""
    success = attendance_system.start_wifi_scanning()
    return jsonify({'success': success, 'message': 'Wi-Fi scanning started' if success else 'Already scanning'})

@app.route('/api/stop_wifi_scan', methods=['POST'])
def stop_wifi_scan():
    """API endpoint to stop Wi-Fi scanning"""
    success = attendance_system.stop_wifi_scanning()
    return jsonify({'success': success, 'message': 'Wi-Fi scanning stopped'})

@app.route('/api/wifi_devices')
def get_wifi_devices():
    """API endpoint to get currently detected Wi-Fi devices"""
    return jsonify(attendance_system.get_wifi_devices_info())

@app.route('/api/wifi_status')
def get_wifi_status():
    """API endpoint to get current Wi-Fi scanning status"""
    return jsonify({
        'scanning': attendance_system.wifi_scanning,
        'thread_alive': attendance_system.wifi_scan_thread.is_alive() if attendance_system.wifi_scan_thread else False
    })

@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests to avoid 404 errors"""
    return '', 204

@app.route('/generate_qr/<student_id>')
def generate_qr(student_id):
    """Generate QR code for student device pairing"""
    conn = sqlite3.connect('attendance.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, mac_address FROM students WHERE student_id = ?', (student_id,))
    student = cursor.fetchone()
    conn.close()
    
    if student:
        qr_data = {
            'student_id': student_id,
            'name': student[0],
            'mac_address': student[1]
        }
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(json.dumps(qr_data))
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for web display
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return render_template('qr_code.html', qr_image=img_str, student=student)
    
    return "Student not found", 404

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info('Client connected')
    emit('status', {'msg': 'Connected to attendance system'})
    
    # Immediately send current devices to the newly connected client
    devices_info = attendance_system.get_detected_devices_info()
    wifi_info = attendance_system.get_wifi_devices_info()
    current_time = datetime.now()
    emit('device_update', {
        'devices': devices_info,
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S')
    })
    emit('wifi_device_update', {
        'devices': wifi_info,
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S')
    })
    logger.info(f"Sent {len(devices_info)} BT devices and {len(wifi_info)} Wi-Fi devices to newly connected client")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info('Client disconnected')

if __name__ == '__main__':
    print("Multi-Modal Classroom Attendance System")
    print("======================================")
    print("Using Bluetooth + Wi-Fi + QR + Manual methods")
    
    # Get and display the network IP address
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        if local_ip.startswith('127.') or local_ip == '::1':
            # Try connecting to a remote address to find local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        print(f"Web interface available at:")
        print(f"  Local access: http://localhost:5001")
        print(f"  Network access: http://{local_ip}:5001")
        print(f"Students can access QR check-in from: http://{local_ip}:5001")
    except Exception as e:
        print(f"Starting web interface on http://localhost:5001")
        print(f"Warning: Could not determine network IP: {e}")
    
    # Start both scanners automatically
    attendance_system.start_scanning()
    attendance_system.start_wifi_scanning()
    
    socketio.run(app, debug=False, host='0.0.0.0', port=5001)
