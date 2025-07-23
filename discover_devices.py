"""
Bluetooth Device Discovery Utility
Simple script to help discover nearby Bluetooth devices for registration
"""

import asyncio
import time
from datetime import datetime
from bleak import BleakScanner

async def scan_for_devices():
    """Scan for nearby Bluetooth LE devices"""
    devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
    return devices

def discover_devices():
    """Discover nearby Bluetooth devices"""
    print("Bluetooth Device Discovery Utility")
    print("=" * 40)
    print("This utility will help you find MAC addresses of student devices.")
    print("Make sure students have their Bluetooth set to 'discoverable' mode.\n")
    
    input("Press Enter to start scanning...")
    
    try:
        while True:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning for devices...")
            
            # Discover devices with names using bleak
            devices = asyncio.run(scan_for_devices())
            
            if devices:
                print(f"Found {len(devices)} device(s):")
                print("-" * 60)
                for device_addr, (device, advertisement_data) in devices.items():
                    name = device.name or advertisement_data.local_name or 'Unknown'
                    print(f"Device: {name}")
                    print(f"MAC:    {device.address}")
                    if advertisement_data.rssi:
                        print(f"RSSI:   {advertisement_data.rssi} dBm")
                    print("-" * 60)
            else:
                print("No devices found.")
            
            print("\nOptions:")
            print("1. Scan again (wait 10 seconds)")
            print("2. Exit")
            
            try:
                choice = input("\nEnter choice (1 or 2): ").strip()
                if choice == '2':
                    break
                elif choice == '1':
                    print("Waiting 10 seconds before next scan...")
                    time.sleep(10)
                else:
                    print("Invalid choice. Scanning again...")
                    time.sleep(2)
            except KeyboardInterrupt:
                break
                
    except Exception as e:
        print(f"Error during Bluetooth scanning: {e}")
        print("\nPossible solutions:")
        print("- Ensure Bluetooth adapter is working")
        print("- Make sure Bluetooth is enabled")
        print("- Check if devices are in discoverable mode")
        
    print("\nDiscovery session ended.")

if __name__ == "__main__":
    discover_devices()
