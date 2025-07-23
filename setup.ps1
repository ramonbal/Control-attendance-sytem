# Bluetooth Classroom Attendance System - Setup Script
# Run this script in PowerShell as Administrator

Write-Host "==================================" -ForegroundColor Green
Write-Host "Bluetooth Attendance System Setup" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green

# Check if Python is installed
Write-Host "`nChecking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found! Please install Python 3.8+ from https://python.org" -ForegroundColor Red
    exit 1
}

# Check if pip is available
Write-Host "`nChecking pip..." -ForegroundColor Yellow
try {
    $pipVersion = pip --version 2>&1
    Write-Host "Found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "pip not found! Please ensure pip is installed with Python" -ForegroundColor Red
    exit 1
}

# Install Python packages
Write-Host "`nInstalling Python packages..." -ForegroundColor Yellow
try {
    pip install -r requirements.txt
    Write-Host "Packages installed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Error installing packages. You may need to install Microsoft Visual C++ Build Tools" -ForegroundColor Red
    Write-Host "Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
}

# Check Bluetooth availability
Write-Host "`nChecking Bluetooth support..." -ForegroundColor Yellow
try {
    $bluetoothDevices = Get-PnpDevice -Class Bluetooth -Status OK
    if ($bluetoothDevices.Count -gt 0) {
        Write-Host "Bluetooth adapter found!" -ForegroundColor Green
    } else {
        Write-Host "No Bluetooth adapter detected. Please ensure Bluetooth is enabled." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not check Bluetooth status" -ForegroundColor Yellow
}

# Create desktop shortcut
Write-Host "`nCreating desktop shortcut..." -ForegroundColor Yellow
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = "$desktopPath\Bluetooth Attendance.lnk"
$targetPath = "powershell.exe"
$arguments = "-Command `"cd '$PWD'; python app.py`""

$WScriptShell = New-Object -ComObject WScript.Shell
$shortcut = $WScriptShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = $PWD
$shortcut.Description = "Bluetooth Classroom Attendance System"
$shortcut.Save()

Write-Host "Desktop shortcut created!" -ForegroundColor Green

Write-Host "`n==================================" -ForegroundColor Green
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green
Write-Host "`nTo start the application:" -ForegroundColor Yellow
Write-Host "1. Double-click the desktop shortcut, OR" -ForegroundColor White
Write-Host "2. Run: python app.py" -ForegroundColor White
Write-Host "3. Open your browser to: http://localhost:5000" -ForegroundColor White
Write-Host "`nNOTE: If PyBluez installation fails, you may need to:" -ForegroundColor Yellow
Write-Host "- Install Microsoft Visual C++ Build Tools" -ForegroundColor White
Write-Host "- Or consider using Windows Subsystem for Linux (WSL)" -ForegroundColor White

Read-Host "`nPress Enter to exit"
