# Multi-Modal Classroom Attendance System

A comprehensive attendance tracking system that supports multiple check-in methods:

- **Bluetooth LE Detection**: Automatic detection of student devices
- **Wi-Fi Network Scanning**: Track devices connected to local network  
- **QR Code Check-in**: Students scan QR codes to check in
- **Manual Check-in**: Teacher-initiated attendance marking

## Features

### Multi-Subject Support
- Create and manage multiple subjects/classes
- Switch between subjects for attendance tracking
- Subject-specific attendance records

### Multiple Attendance Methods
1. **Bluetooth LE**: Automatic detection of registered student devices
2. **Wi-Fi Scanning**: Detection of devices on local network
3. **QR Code**: Generate session-based QR codes for student check-in
4. **Manual Entry**: Direct teacher input for attendance

### Student Management
- Add students individually or import from Excel
- Associate Bluetooth and Wi-Fi MAC addresses with students
- Student database with ID and name management

### Real-time Dashboard
- Live view of detected devices
- Current attendance status
- Multi-modal detection display
- WebSocket-based real-time updates
- **QR Code Generation**: Generate QR codes for easy student device verification
- **Web Interface**: Clean, responsive web interface accessible from any device

## System Requirements

- Windows 10/11 (with Bluetooth support)
- Python 3.8 or higher
- Bluetooth adapter (built-in or USB)

## Installation

### 1. Install Python Dependencies

```powershell
# Navigate to the project directory
cd "c:\Dades\Cloud\OneDrive - Computer Vision Center\prj\varis\controlBT"

# Install required packages
pip install -r requirements.txt
```

### 2. Bluetooth Setup (Windows)

The application uses PyBluez which requires Microsoft Visual C++ 14.0. If you encounter installation issues:

1. Install Microsoft C++ Build Tools:
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Or install Visual Studio Community

2. Alternative: Use the Windows Subsystem for Linux (WSL) for better Bluetooth support

### 3. Run the Application

```powershell
python app.py
```

The application will start on http://localhost:5000

## Usage Guide

### 1. Initial Setup

1. Start the application
2. Open your web browser to http://localhost:5000
3. Navigate to the "Students" section
4. Add students with their information and Bluetooth MAC addresses

### 2. Finding Student MAC Addresses

**Method 1: Using the Scanner**
1. Ask students to make their phones discoverable (Settings → Bluetooth → Make discoverable)
2. Use the Dashboard scanner to detect nearby devices
3. Note the MAC addresses of detected devices

**Method 2: Manual Collection**
- **Android**: Settings → About Phone → Status → Bluetooth address
- **iPhone**: Settings → General → About → Bluetooth address

### 3. Taking Attendance

1. Start the Bluetooth scanner from the Dashboard
2. Students should have Bluetooth enabled (not necessarily discoverable)
3. The system will automatically detect registered devices
4. View real-time attendance on the Dashboard
5. Check attendance records in the "Attendance" section

## How It Works

### Technical Overview

1. **Bluetooth Discovery**: Uses PyBluez to scan for nearby Bluetooth devices
2. **Device Matching**: Compares detected MAC addresses with registered students
3. **Attendance Logging**: Records first detection and last seen times
4. **Real-time Updates**: Uses WebSockets to push live updates to the web interface

### Privacy Considerations

- Only MAC addresses are stored, no personal device information
- Detection requires devices to have Bluetooth enabled
- Students maintain control over their device visibility
- No data is transmitted from student devices

## Configuration

### Database

The application uses SQLite database (`attendance.db`) with three main tables:
- `students`: Student information and MAC addresses
- `attendance`: Daily attendance records
- `sessions`: Class session management (future enhancement)

### Scanning Parameters

You can modify scanning behavior in `app.py`:
- Scan duration: Currently 8 seconds per scan
- Scan interval: 30 seconds between scans
- Detection timeout: 5 minutes (devices considered "present")

## Troubleshooting

### Common Issues

1. **Bluetooth not working**
   - Ensure Bluetooth adapter is enabled
   - Check Windows Bluetooth drivers
   - Try running as administrator

2. **No devices detected**
   - Students need Bluetooth enabled
   - Some devices may not be discoverable by default
   - Check proximity (Bluetooth range ~10 meters)

3. **Installation errors**
   - Install Microsoft Visual C++ Build Tools
   - Consider using WSL for Linux-based Bluetooth stack

### Logs and Debugging

- Check console output for Bluetooth scan errors
- Web browser developer console for frontend issues
- Database file `attendance.db` for data inspection

## Limitations

- Requires students to keep Bluetooth enabled
- Detection range limited to ~10 meters
- Some devices may randomize MAC addresses (newer iPhones)
- Windows Bluetooth stack limitations

## Future Enhancements

- Student mobile app for easier registration
- Automatic MAC address detection during registration
- Integration with school management systems
- Advanced reporting and analytics
- Support for multiple classrooms
- Session management with start/end times

## Security Notes

- Change the default secret key in production
- Consider network security for classroom deployment
- MAC addresses are considered personally identifiable information
- Implement proper data retention policies

## License

This project is for educational purposes. Please ensure compliance with your institution's privacy policies and applicable laws regarding student data collection.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review console logs for error messages
3. Ensure all dependencies are properly installed
4. Verify Bluetooth hardware compatibility
