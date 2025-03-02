# Fingerprint Authentication Tool - Usage Guide

This document provides detailed instructions on how to use the Fingerprint Authentication Tool with your ZKTeco Live20R fingerprint scanner on Ubuntu 22.04.

## Table of Contents

1. [Setup and Installation](#setup-and-installation)
2. [Interactive Mode](#interactive-mode)
   - [Registering Fingerprints](#registering-fingerprints)
   - [Verifying Fingerprints](#verifying-fingerprints)
   - [Identifying Fingerprints](#identifying-fingerprints)
   - [Managing Users](#managing-users)
   - [Adjusting Settings](#adjusting-settings)
3. [Command-line Mode](#command-line-mode)
   - [Basic Commands](#basic-commands)
   - [Advanced Usage](#advanced-usage)
4. [Integration Examples](#integration-examples)
5. [Performance Optimization](#performance-optimization)
6. [Backup and Recovery](#backup-and-recovery)
7. [Troubleshooting](#troubleshooting)

## Setup and Installation

### Prerequisites

- ZKTeco Live20R fingerprint scanner
- Ubuntu 22.04 (x86_64)
- Python 3.6 or higher
- ZKFinger SDK libraries

### Installation Steps

1. Connect your ZKTeco Live20R scanner to a USB port.

2. Install the required Python package:
   ```bash
   pip install click
   ```

3. Clone the repository:
   ```bash
   git clone https://github.com/araray/avauth-fingerprint.git
   cd avauth-fingerprint
   ```

4. Copy the ZKFinger SDK shared library to the `libs` directory:
   ```bash
   mkdir -p libs
   cp /path/to/libzkfp.so libs/
   ```

5. Ensure the fingerprint scanner has correct permissions:
   ```bash
   # List USB devices
   lsusb

   # Find your ZKTeco device and note the bus and device numbers
   # Example output line: Bus 001 Device 005: ID 1b55:0200 ZKTeco Inc. Live20R Fingerprint Scanner

   # Set permissions (replace 001 and 005 with your values)
   sudo chmod a+rw /dev/bus/usb/001/005
   ```

## Interactive Mode

To start the tool in interactive mode:

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py
```

You'll see a menu with options to register, verify, and identify fingerprints, as well as manage users and settings.

### Registering Fingerprints

1. From the main menu, select **Option 1: Register fingerprint**
2. Enter a unique username when prompted
3. Enter the number of samples to capture (default is 3)
4. When prompted, place your finger on the scanner
5. Remove your finger when instructed and place it again for subsequent samples
6. If all samples match, you'll see a "Registration successful" message

Tips for successful registration:
- Ensure your finger is clean and dry
- Place your finger consistently in the same position for all samples
- Apply gentle pressure - not too light, not too heavy
- Try to center your finger on the scanner

### Verifying Fingerprints

1. From the main menu, select **Option 2: Verify fingerprint**
2. Enter the username to verify against
3. Place your finger on the scanner when prompted
4. The system will compare your fingerprint with the stored template
5. You'll see a "Verification successful" or "Verification failed" message

### Identifying Fingerprints

1. From the main menu, select **Option 3: Identify fingerprint**
2. Place your finger on the scanner when prompted
3. The system will compare your fingerprint with all stored templates
4. If a match is found, the corresponding username will be displayed

### Managing Users

#### Listing Users

1. From the main menu, select **Option 4: List registered users**
2. The system will display all registered users with their IDs and registration dates

#### Deleting Users

1. From the main menu, select **Option 5: Delete user**
2. Enter the username to delete
3. Confirm the deletion when prompted

### Adjusting Settings

#### Matching Threshold

1. From the main menu, select **Option 6: Set matching threshold**
2. Enter a new threshold value (0-100)
   - Higher values (e.g., 70-80) require closer matches but reduce false positives
   - Lower values (e.g., 40-50) are more lenient but may increase false positives

## Command-line Mode

The tool supports command-line operations for easy integration with scripts and other applications.

### Basic Commands

#### Register a Fingerprint

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py register --name "John Doe"

# Specify the number of samples
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py register --name "John Doe" --samples 4
```

#### Verify a Fingerprint

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py verify --name "John Doe"
```

#### Identify a Fingerprint

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py identify
```

#### List Registered Users

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py list
```

#### Delete a User

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py delete --name "John Doe"
```

#### Set Matching Threshold

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py threshold --value 60
```

### Advanced Usage

#### Using a Different Database

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py --db-path /path/to/database.db list
```

#### Specifying a Different Library Path

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py --lib-path /path/to/libzkfp.so list
```

#### Enabling Debug Logging

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py --debug identify
```

## Integration Examples

### Shell Script Integration

You can create a shell script to automate fingerprint authentication:

```bash
#!/bin/bash
# auth.sh

USERNAME="$1"
if [ -z "$USERNAME" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

export LD_LIBRARY_PATH=$PWD/libs
OUTPUT=$(python3 improved_fingerprint_tool.py verify --name "$USERNAME")

if echo "$OUTPUT" | grep -q "Verification successful"; then
    echo "Access granted for user: $USERNAME"
    exit 0
else
    echo "Access denied"
    exit 1
fi
```

Usage:
```bash
chmod +x auth.sh
./auth.sh "John Doe"
```

### Systemd Service Integration

You can create a systemd service to run the fingerprint tool as a background service:

1. Create a service file:
   ```bash
   sudo nano /etc/systemd/system/fingerprint-auth.service
   ```

2. Add the following content:
   ```ini
   [Unit]
   Description=Fingerprint Authentication Service
   After=network.target

   [Service]
   User=your_username
   WorkingDirectory=/path/to/avauth-fingerprint
   Environment="LD_LIBRARY_PATH=/path/to/avauth-fingerprint/libs"
   ExecStart=/usr/bin/python3 /path/to/avauth-fingerprint/improved_fingerprint_tool.py --db-path /path/to/fingerprints.db

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl enable fingerprint-auth.service
   sudo systemctl start fingerprint-auth.service
   ```

4. Check the service status:
   ```bash
   sudo systemctl status fingerprint-auth.service
   ```

## Performance Optimization

### Database Optimization

For large databases with many users:

1. Create indices on frequently queried columns:
   ```sql
   CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);
   ```

2. Vacuum the database periodically to optimize performance:
   ```bash
   sqlite3 fingerprints.db "VACUUM;"
   ```

### Acquisition Settings

For faster fingerprint acquisition:

1. Reduce the settle time and acquisition delay in the code:
   ```python
   # In improved_fingerprint_tool.py
   SETTLE_TIME = 1.0  # Reduce from 2.0 seconds
   ACQUISITION_DELAY = 0.3  # Reduce from 0.5 seconds
   ```

## Backup and Recovery

### Database Backup

Regularly back up your fingerprint database:

```bash
# Create a backup
cp fingerprints.db fingerprints.db.backup

# Or create a timestamped backup
cp fingerprints.db fingerprints.db.$(date +%Y%m%d)
```

### Database Recovery

Restore from a backup if needed:

```bash
cp fingerprints.db.backup fingerprints.db
```

## Troubleshooting

### Common Issues and Solutions

1. **"No device connected" error**
   - Make sure the scanner is properly connected
   - Check USB permissions with `ls -l /dev/bus/usb/XXX/YYY`
   - Try a different USB port

2. **"Failed to capture image" error**
   - Clean the scanner surface
   - Ensure your finger is not too dry or wet
   - Position your finger correctly on the center of the scanner

3. **"Failed to extract fingerprint template" error**
   - Try applying more pressure when placing your finger
   - Make sure your finger is properly centered on the scanner
   - The finger might be too dry; moistening it slightly can help

4. **Database errors**
   - Check if the database file is writable: `ls -l fingerprints.db`
   - If the database is corrupted, restore from a backup

5. **High false rejection rate**
   - Lower the matching threshold: `python3 improved_fingerprint_tool.py threshold --value 50`
   - Register multiple fingerprints for the same user with different names (e.g., "john_index", "john_thumb")

### Debugging

For detailed debugging information:

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py --debug register --name "Test User"
```

This will provide verbose output in the terminal and detailed logs in `fingerprint_tool.log`.

### Log Analysis

The log file contains detailed information about each operation:

```bash
tail -f fingerprint_tool.log
```

Look for error messages and warnings to diagnose issues.
