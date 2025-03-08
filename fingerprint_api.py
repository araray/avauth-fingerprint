#!/usr/bin/env python3
"""
Fingerprint API Tool
===================

A JSON API wrapper for the ZKTeco fingerprint authentication tool.
This script provides a programmatic interface for other scripts to interact
with the fingerprint tool via structured JSON responses.

Features:
- JSON-formatted responses for all operations
- Complete error handling with proper error codes
- Support for all fingerprint operations (register, verify, identify, etc.)
- Designed for integration with other applications

Usage:
    # Register a fingerprint and get JSON response
    python fingerprint_api.py register --name "John Doe" --json

    # Verify a fingerprint
    python fingerprint_api.py verify --name "John Doe" --json

    # Identify a fingerprint
    python fingerprint_api.py identify --json

    # Return the raw template for custom processing
    python fingerprint_api.py acquire --raw --json

Environment:
    Ubuntu 22.04 x86_64 with ZKTeco Live20R fingerprint scanner

Author: Araray
Date: 2025-03-08
"""

import os
import sys
import time
import base64
import json
import logging
import builtins
import ctypes
import click
from typing import Dict, Any, Optional, Union, List, Tuple

# Constants
DEFAULT_LOG_PATH = "fingerprint_api.log"
DEFAULT_DB_PATH = "fingerprints.db"
DEFAULT_SAMPLES = 3
DEFAULT_MATCH_THRESHOLD = 60
SUCCESS_CODE = 0
ERROR_CODE_BASE = 1000
ERROR_CODES = {
    "UNKNOWN_ERROR": ERROR_CODE_BASE + 0,
    "INITIALIZATION_ERROR": ERROR_CODE_BASE + 1,
    "DEVICE_ERROR": ERROR_CODE_BASE + 2,
    "DATABASE_ERROR": ERROR_CODE_BASE + 3,
    "ACQUISITION_ERROR": ERROR_CODE_BASE + 4,
    "REGISTRATION_ERROR": ERROR_CODE_BASE + 5,
    "VERIFICATION_ERROR": ERROR_CODE_BASE + 6,
    "IDENTIFICATION_ERROR": ERROR_CODE_BASE + 7,
    "USER_MANAGEMENT_ERROR": ERROR_CODE_BASE + 8,
    "INVALID_INPUT": ERROR_CODE_BASE + 9,
    "PERMISSION_ERROR": ERROR_CODE_BASE + 10,
}

# Setup logging - file only, no console output
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(DEFAULT_LOG_PATH)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)
logger.propagate = False

# Redirect stdout/stderr to capture all output from the imported modules
# We'll restore them later for JSON output
original_stdout = sys.stdout
original_stderr = sys.stderr
null_file = open(os.devnull, 'w')
sys.stdout = null_file
sys.stderr = null_file

try:
    # Import the fingerprint manager from the main tool
    try:
        from fingerprint_tool import FingerprintManager, zkfinger, TEMPLATE_SIZE
    except ImportError:
        # Restore stdout/stderr for the error message
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        print("Error: Could not import fingerprint_tool module")
        sys.exit(1)
finally:
    # Restore stdout/stderr
    sys.stdout = original_stdout
    sys.stderr = original_stderr


class FingerprintAPI:
    """
    API wrapper for the fingerprint tool that provides JSON-formatted responses.
    """

    def __init__(self, lib_path: str = "libzkfp.so", db_path: str = DEFAULT_DB_PATH):
        """
        Initialize the fingerprint API.

        Args:
            lib_path: Path to the ZKFinger SDK library
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        self.fp_manager = None
        self.lib_path = lib_path

    def _initialize(self) -> Dict[str, Any]:
        """
        Initialize the fingerprint manager if not already initialized.

        Returns:
            Dict with success/error status
        """
        if self.fp_manager is not None:
            return {"status": "success", "code": SUCCESS_CODE}

        try:
            # Redirect stdout/stderr during initialization
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                self.fp_manager = FingerprintManager(lib_path=self.lib_path, db_path=self.db_path)
                return {"status": "success", "code": SUCCESS_CODE}
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        except zkfinger.ZKFingerError as e:
            logger.error(f"Fingerprint manager initialization failed: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["INITIALIZATION_ERROR"],
                "message": f"Initialization failed: {str(e)}",
                "error_type": "initialization_error"
            }
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["UNKNOWN_ERROR"],
                "message": f"Unexpected error: {str(e)}",
                "error_type": "unknown_error"
            }

    def cleanup(self):
        """Clean up resources when done."""
        if self.fp_manager:
            try:
                # Redirect stdout/stderr during cleanup
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                sys.stdout = open(os.devnull, 'w')
                sys.stderr = open(os.devnull, 'w')

                try:
                    self.fp_manager.cleanup()
                    self.fp_manager = None
                finally:
                    # Restore stdout/stderr
                    sys.stdout.close()
                    sys.stderr.close()
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")

    def acquire_fingerprint(self, raw: bool = False) -> Dict[str, Any]:
        """
        Acquire a fingerprint from the scanner.

        Args:
            raw: If True, include the raw template data in base64 format

        Returns:
            Dict with success/error status and template info
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        try:
            # Acquire fingerprint with stdout/stderr redirected
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Message will be invisible due to redirection
                message = "Place your finger on the scanner to acquire fingerprint"
                image_data, template_data = self.fp_manager._acquire_fingerprint(message)
            except Exception as e:
                logger.error(f"Error during fingerprint acquisition: {e}")
                raise
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            response = {
                "status": "success",
                "code": SUCCESS_CODE,
                "template_size": len(template_data),
                "message": "Fingerprint acquired successfully"
            }

            if raw:
                # Convert binary template to base64 for transmission
                template_b64 = base64.b64encode(template_data).decode('utf-8')
                response["template"] = template_b64

            return response

        except zkfinger.ZKFingerError as e:
            logger.error(f"Fingerprint acquisition failed: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["ACQUISITION_ERROR"],
                "message": f"Acquisition failed: {str(e)}",
                "error_type": "acquisition_error"
            }
        except Exception as e:
            logger.error(f"Unexpected error during fingerprint acquisition: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["UNKNOWN_ERROR"],
                "message": f"Unexpected error: {str(e)}",
                "error_type": "unknown_error"
            }

    def register_fingerprint(self, name: str, num_samples: int = DEFAULT_SAMPLES) -> Dict[str, Any]:
        """
        Register a new fingerprint.

        Args:
            name: User name to associate with the fingerprint
            num_samples: Number of fingerprint samples to capture

        Returns:
            Dict with success/error status
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        if not name:
            return {
                "status": "error",
                "code": ERROR_CODES["INVALID_INPUT"],
                "message": "User name cannot be empty",
                "error_type": "invalid_input"
            }

        try:
            # Redirect stdout/stderr during registration
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Check if user already exists
                users = self.fp_manager.list_users()
                user_exists = any(user['name'] == name for user in users)

                # Register fingerprint
                result = self.fp_manager.register_fingerprint(name, num_samples=num_samples)
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            if result:
                response = {
                    "status": "success",
                    "code": SUCCESS_CODE,
                    "message": f"User '{name}' registered successfully",
                    "user": {
                        "name": name,
                        "samples": num_samples,
                        "overwritten": user_exists
                    }
                }
            else:
                response = {
                    "status": "error",
                    "code": ERROR_CODES["REGISTRATION_ERROR"],
                    "message": "Registration failed",
                    "error_type": "registration_error"
                }

            return response

        except zkfinger.ZKFingerError as e:
            logger.error(f"Fingerprint registration failed: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["REGISTRATION_ERROR"],
                "message": f"Registration failed: {str(e)}",
                "error_type": "registration_error"
            }
        except Exception as e:
            logger.error(f"Unexpected error during fingerprint registration: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["UNKNOWN_ERROR"],
                "message": f"Unexpected error: {str(e)}",
                "error_type": "unknown_error"
            }

    def verify_fingerprint(self, name: str) -> Dict[str, Any]:
        """
        Verify a fingerprint against a specific user's template.

        Args:
            name: User name to verify against

        Returns:
            Dict with success/error status and match information
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        if not name:
            return {
                "status": "error",
                "code": ERROR_CODES["INVALID_INPUT"],
                "message": "User name cannot be empty",
                "error_type": "invalid_input"
            }

        try:
            # Redirect stdout/stderr during verification
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Check if user exists
                users = self.fp_manager.list_users()
                user_exists = any(user['name'] == name for user in users)

                if not user_exists:
                    # Restore stdout/stderr before returning
                    sys.stdout.close()
                    sys.stderr.close()
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr

                    return {
                        "status": "error",
                        "code": ERROR_CODES["VERIFICATION_ERROR"],
                        "message": f"User '{name}' not found in the database",
                        "error_type": "user_not_found"
                    }

                # Verify fingerprint
                result = self.fp_manager.verify_fingerprint(name)
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            if result:
                response = {
                    "status": "success",
                    "code": SUCCESS_CODE,
                    "message": f"Verification successful for user '{name}'",
                    "match": True,
                    "user": {"name": name}
                }
            else:
                response = {
                    "status": "failure",  # Not an error, just a failed match
                    "code": SUCCESS_CODE,
                    "message": f"Fingerprint does not match user '{name}'",
                    "match": False,
                    "user": {"name": name}
                }

            return response

        except zkfinger.ZKFingerError as e:
            logger.error(f"Fingerprint verification failed: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["VERIFICATION_ERROR"],
                "message": f"Verification failed: {str(e)}",
                "error_type": "verification_error"
            }
        except Exception as e:
            logger.error(f"Unexpected error during fingerprint verification: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["UNKNOWN_ERROR"],
                "message": f"Unexpected error: {str(e)}",
                "error_type": "unknown_error"
            }

    def identify_fingerprint(self) -> Dict[str, Any]:
        """
        Identify a fingerprint against all registered templates.

        Returns:
            Dict with success/error status and identification information
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        try:
            # Redirect stdout/stderr during identification
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Identify fingerprint
                identified_user = self.fp_manager.identify_fingerprint()
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            if identified_user:
                response = {
                    "status": "success",
                    "code": SUCCESS_CODE,
                    "message": f"Fingerprint identified as user '{identified_user}'",
                    "match": True,
                    "user": {"name": identified_user}
                }
            else:
                response = {
                    "status": "failure",  # Not an error, just no match found
                    "code": SUCCESS_CODE,
                    "message": "No matching fingerprint found",
                    "match": False
                }

            return response

        except zkfinger.ZKFingerError as e:
            logger.error(f"Fingerprint identification failed: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["IDENTIFICATION_ERROR"],
                "message": f"Identification failed: {str(e)}",
                "error_type": "identification_error"
            }
        except Exception as e:
            logger.error(f"Unexpected error during fingerprint identification: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["UNKNOWN_ERROR"],
                "message": f"Unexpected error: {str(e)}",
                "error_type": "unknown_error"
            }

    def list_users(self) -> Dict[str, Any]:
        """
        List all registered users.

        Returns:
            Dict with success/error status and user list
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        try:
            # Redirect stdout/stderr during list operation
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # List users
                users = self.fp_manager.list_users()
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            response = {
                "status": "success",
                "code": SUCCESS_CODE,
                "message": f"Found {len(users)} registered users",
                "count": len(users),
                "users": users
            }

            return response

        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["USER_MANAGEMENT_ERROR"],
                "message": f"Failed to list users: {str(e)}",
                "error_type": "user_management_error"
            }

    def delete_user(self, name: str) -> Dict[str, Any]:
        """
        Delete a user from the database.

        Args:
            name: User name to delete

        Returns:
            Dict with success/error status
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        if not name:
            return {
                "status": "error",
                "code": ERROR_CODES["INVALID_INPUT"],
                "message": "User name cannot be empty",
                "error_type": "invalid_input"
            }

        try:
            # Redirect stdout/stderr during deletion
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Delete user
                result = self.fp_manager.delete_user(name)
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            if result:
                response = {
                    "status": "success",
                    "code": SUCCESS_CODE,
                    "message": f"User '{name}' deleted successfully"
                }
            else:
                response = {
                    "status": "error",
                    "code": ERROR_CODES["USER_MANAGEMENT_ERROR"],
                    "message": f"User '{name}' not found or could not be deleted",
                    "error_type": "user_not_found"
                }

            return response

        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["USER_MANAGEMENT_ERROR"],
                "message": f"Failed to delete user: {str(e)}",
                "error_type": "user_management_error"
            }

    def set_threshold(self, threshold: int) -> Dict[str, Any]:
        """
        Set the fingerprint matching threshold.

        Args:
            threshold: Matching threshold (0-100)

        Returns:
            Dict with success/error status
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        if threshold < 0 or threshold > 100:
            return {
                "status": "error",
                "code": ERROR_CODES["INVALID_INPUT"],
                "message": "Threshold must be between 0 and 100",
                "error_type": "invalid_input"
            }

        try:
            # Redirect stdout/stderr during threshold setting
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Set threshold
                result = self.fp_manager.set_threshold(threshold)
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            if result:
                response = {
                    "status": "success",
                    "code": SUCCESS_CODE,
                    "message": f"Match threshold set to {threshold}",
                    "threshold": threshold
                }
            else:
                response = {
                    "status": "error",
                    "code": ERROR_CODES["DEVICE_ERROR"],
                    "message": "Failed to set threshold",
                    "error_type": "device_error"
                }

            return response

        except Exception as e:
            logger.error(f"Error setting threshold: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["DEVICE_ERROR"],
                "message": f"Failed to set threshold: {str(e)}",
                "error_type": "device_error"
            }

    def get_info(self) -> Dict[str, Any]:
        """
        Get system information, including device status and user count.

        Returns:
            Dict with system information
        """
        init_result = self._initialize()
        if init_result["status"] != "success":
            return init_result

        try:
            # Redirect stdout/stderr during info retrieval
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')

            try:
                # Get system info
                device_count = self.fp_manager.sdk.get_device_count()
                users = self.fp_manager.list_users()

                # Get device parameters if possible
                device_info = {}
                if self.fp_manager.device:
                    try:
                        device_info = {
                            "width": self.fp_manager.device.get_parameter(1),  # Width
                            "height": self.fp_manager.device.get_parameter(2),  # Height
                            "dpi": self.fp_manager.device.get_parameter(3),     # DPI
                        }
                    except:
                        device_info = {
                            "width": "unknown",
                            "height": "unknown",
                            "dpi": "unknown"
                        }
            finally:
                # Restore stdout/stderr
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            response = {
                "status": "success",
                "code": SUCCESS_CODE,
                "system_info": {
                    "device_count": device_count,
                    "user_count": len(users),
                    "database_path": self.db_path,
                    "library_path": self.lib_path,
                    "template_size": TEMPLATE_SIZE,
                    "match_threshold": self.fp_manager.match_threshold,
                    "device": device_info
                }
            }

            return response

        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {
                "status": "error",
                "code": ERROR_CODES["UNKNOWN_ERROR"],
                "message": f"Failed to get system info: {str(e)}",
                "error_type": "unknown_error"
            }


# Click CLI commands

@click.group()
@click.option('--lib-path', default="libzkfp.so", help="Path to the ZKFinger SDK library")
@click.option('--db-path', default=DEFAULT_DB_PATH, help="Path to the SQLite database")
@click.option('--debug/--no-debug', default=False, help="Enable debug logging")
@click.option('--json/--no-json', default=True, help="Output results as JSON")
@click.pass_context
def cli(ctx, lib_path, db_path, debug, json):
    """
    Fingerprint API tool for programmatic interaction with ZKTeco scanners.

    This tool provides JSON-formatted responses for all operations.
    """
    # Set debug level if requested
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Store configuration in context
    ctx.ensure_object(dict)
    ctx.obj['LIB_PATH'] = lib_path
    ctx.obj['DB_PATH'] = db_path
    ctx.obj['JSON'] = json
    ctx.obj['API'] = FingerprintAPI(lib_path=lib_path, db_path=db_path)


@cli.command()
@click.option('--raw/--no-raw', default=False, help="Include raw template data in the output")
@click.pass_context
def acquire(ctx, raw):
    """
    Acquire a fingerprint from the scanner and return template information.

    If --raw is specified, the raw template data will be included in the response as a base64 string.
    """
    api = ctx.obj['API']
    try:
        result = api.acquire_fingerprint(raw=raw)
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "success":
                click.echo(f"Fingerprint acquired successfully (size: {result['template_size']} bytes)")
                if raw:
                    click.echo(f"Template data included in JSON output")
            else:
                click.echo(f"Error: {result['message']}")
    finally:
        api.cleanup()


@cli.command()
@click.option('--name', required=True, help="User name to associate with the fingerprint")
@click.option('--samples', default=DEFAULT_SAMPLES, help="Number of samples to capture")
@click.pass_context
def register(ctx, name, samples):
    """
    Register a new fingerprint and associate it with a user name.
    """
    api = ctx.obj['API']
    try:
        result = api.register_fingerprint(name, num_samples=samples)
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "success":
                click.echo(result["message"])
            else:
                click.echo(f"Error: {result['message']}")
    finally:
        api.cleanup()


@cli.command()
@click.option('--name', required=True, help="User name to verify against")
@click.pass_context
def verify(ctx, name):
    """
    Verify a fingerprint against a specific user's registered template.
    """
    api = ctx.obj['API']
    try:
        result = api.verify_fingerprint(name)
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "error":
                click.echo(f"Error: {result['message']}")
            elif result["match"]:
                click.echo(f"Verification successful for user '{name}'")
            else:
                click.echo(f"Verification failed for user '{name}'")
    finally:
        api.cleanup()


@cli.command()
@click.pass_context
def identify(ctx):
    """
    Identify a fingerprint against all registered templates.
    """
    api = ctx.obj['API']
    try:
        result = api.identify_fingerprint()
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "error":
                click.echo(f"Error: {result['message']}")
            elif result["match"]:
                click.echo(f"Identified user: {result['user']['name']}")
            else:
                click.echo("No matching fingerprint found")
    finally:
        api.cleanup()


@cli.command()
@click.pass_context
def list(ctx):
    """
    List all registered users.
    """
    api = ctx.obj['API']
    try:
        result = api.list_users()
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "success":
                click.echo(f"Found {result['count']} registered users:")
                for user in result["users"]:
                    click.echo(f"- {user['name']} (ID: {user['id']}, Added: {user['date_added']})")
            else:
                click.echo(f"Error: {result['message']}")
    finally:
        api.cleanup()


@cli.command()
@click.option('--name', required=True, help="User name to delete")
@click.pass_context
def delete(ctx, name):
    """
    Delete a user from the database.
    """
    api = ctx.obj['API']
    try:
        result = api.delete_user(name)
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "success":
                click.echo(result["message"])
            else:
                click.echo(f"Error: {result['message']}")
    finally:
        api.cleanup()


@cli.command()
@click.option('--value', type=int, required=True, help="Threshold value (0-100)")
@click.pass_context
def threshold(ctx, value):
    """
    Set the fingerprint matching threshold.
    """
    api = ctx.obj['API']
    try:
        result = api.set_threshold(value)
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "success":
                click.echo(result["message"])
            else:
                click.echo(f"Error: {result['message']}")
    finally:
        api.cleanup()


@cli.command()
@click.pass_context
def info(ctx):
    """
    Get system information including device status and user count.
    """
    api = ctx.obj['API']
    try:
        result = api.get_info()
        if ctx.obj['JSON']:
            click.echo(json.dumps(result, indent=2))
        else:
            # Text output for human readability
            if result["status"] == "success":
                info = result["system_info"]
                click.echo("System Information:")
                click.echo(f"- Device count: {info['device_count']}")
                click.echo(f"- User count: {info['user_count']}")
                click.echo(f"- Database path: {info['database_path']}")
                click.echo(f"- Match threshold: {info['match_threshold']}")
                click.echo("Device Information:")
                for key, value in info['device'].items():
                    click.echo(f"- {key}: {value}")
                else:
                    click.echo(f"Error: {result['message']}")
    finally:
        api.cleanup()

if __name__ == "__main__":
    # Run the CLI
    cli()
