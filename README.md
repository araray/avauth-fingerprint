# Fingerprint Authentication Tool

A comprehensive utility for ZKTeco Live20R fingerprint scanners that provides seamless fingerprint registration, verification, and identification.

## Features

- **Interactive Mode**: User-friendly menu-driven interface
- **Command-line Interface**: Efficient CLI using Click for automation
- **Robust Fingerprint Acquisition**: Improved error handling and retry mechanisms
- **Enhanced SDK Integration**: Better utilization of ZKFinger SDK capabilities
- **Improved Matching Algorithm**: Using the SDK's built-in matching functionality
- **Database Integration**: Proper SQLite database operations
- **Comprehensive Logging**: Detailed logs for troubleshooting
- **Thread-Safety**: Robust concurrent operation support

## System Requirements

- **Operating System**: Ubuntu 22.04 (x86_64)
- **Hardware**: ZKTeco Live20R fingerprint scanner
- **Dependencies**: Python 3.6+, Click, SQLite3

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/araray/avauth-fingerprint.git
   cd avauth-fingerprint
   ```

2. Ensure the ZKFinger SDK libraries are in the `libs` directory:
   ```bash
   mkdir -p libs
   # Copy libzkfp.so to the libs directory
   ```

3. Install Python dependencies:
   ```bash
   pip install click
   ```

## Usage

### Interactive Mode

Run the tool in interactive mode:

```bash
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py
```

This will present a menu with the following options:
1. Register fingerprint
2. Verify fingerprint
3. Identify fingerprint
4. List registered users
5. Delete user
6. Set matching threshold
7. Exit

### Command-line Mode

The tool also supports command-line operation for automation:

```bash
# Register a new fingerprint
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py register --name "John Doe"

# Verify a fingerprint
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py verify --name "John Doe"

# Identify a fingerprint
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py identify

# List registered users
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py list

# Delete a user
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py delete --name "John Doe"

# Set matching threshold
LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py threshold --value 60
```

## Command-line Options

```
Usage: improved_fingerprint_tool.py [OPTIONS] COMMAND [ARGS]...

  Fingerprint authentication tool for ZKTeco Live20R scanners

Options:
  --lib-path TEXT        Path to the ZKFinger SDK library
  --db-path TEXT         Path to the SQLite database
  --debug / --no-debug   Enable debug logging
  --help                 Show this message and exit

Commands:
  delete      Delete a user from the database
  identify    Identify a fingerprint against all registered users
  list        List all registered users
  register    Register a new fingerprint
  threshold   Set the fingerprint matching threshold
  verify      Verify a fingerprint against a specific user
```

## Advanced Configuration

The tool creates a SQLite database (`fingerprints.db`) in the current directory by default. You can specify an alternative database path using the `--db-path` option.

Logs are written to `fingerprint_tool.log` in the current directory.

## Troubleshooting

Common issues and solutions:

1. **Device not found**: Ensure the fingerprint scanner is properly connected and that the ZKFinger SDK libraries are correctly installed.

2. **Acquisition failures**: If you frequently see "Failed to capture image" errors:
   - Clean the scanner surface
   - Make sure your finger is properly placed
   - Adjust the retry settings in the code

3. **False rejections/matches**: Try adjusting the matching threshold:
   - Higher values (e.g., 70-80) will reduce false positives but might increase false negatives
   - Lower values (e.g., 40-50) will increase matches but might cause false positives

4. **Permission issues**: Make sure you have read/write permissions to the device:
   ```bash
   sudo chmod a+rw /dev/bus/usb/XXX/YYY
   ```
   (Replace XXX/YYY with the appropriate USB device path)

## Architecture

The tool consists of three main components:

1. **ZKFinger SDK Wrapper**: Enhanced Python interface to the C library (`zkfinger_enhanced.py`)
2. **Fingerprint Manager**: Core logic for fingerprint operations
3. **User Interface**: Interactive and command-line interfaces using Click

## Security Considerations

- The fingerprint templates are stored in a SQLite database as binary data
- Consider encrypting the database file in production environments
- For high-security applications, implement additional authentication factors

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- ZKTeco for providing the fingerprint scanner and SDK
- Click library for the command-line interface

## Author

Araray Velho (2025)
