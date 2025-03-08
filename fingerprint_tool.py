#!/usr/bin/env python3
"""
Enhanced Fingerprint Authentication Tool
========================================

A comprehensive utility for ZKTeco Live20R fingerprint scanners that provides
fingerprint registration, verification, and identification.

Features:
- Interactive and command-line modes (using Click)
- Robust fingerprint acquisition with improved error handling
- Proper database operations with SQLite
- Improved matching algorithm using ZKFinger SDK's built-in matching
- Hardware-specific optimizations
- Comprehensive logging

Usage:
    # Interactive mode
    LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py

    # Command-line mode
    LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py register --name "John Doe"
    LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py verify --name "John Doe"
    LD_LIBRARY_PATH=$PWD/libs python3 improved_fingerprint_tool.py identify

Environment:
    Ubuntu 22.04 x86_64 with ZKTeco Live20R fingerprint scanner

Author: Araray
Date: 2025-03-02
"""

import time
import sqlite3
import logging
import click
import ctypes

from typing import Optional, Tuple, List, Dict, Any

# Import the ZKFinger module
import zkfinger

# Constants
DB_PATH = "fingerprints.db"
LOG_PATH = "fingerprint_tool.log"
TEMPLATE_SIZE = 2048  # Maximum template size as defined in libzkfptype.h
DEFAULT_MATCH_THRESHOLD = 60  # Default threshold for matching (0-100)
DEFAULT_SAMPLES = 3  # Default number of samples for registration
MAX_RETRIES = 10  # Max retries for fingerprint acquisition
ACQUISITION_DELAY = 0.5  # Delay between acquisition attempts
SETTLE_TIME = 2.0  # Initial sensor settle time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class FingerprintManager:
    """
    Manages fingerprint operations including database interactions
    and interfacing with the ZKFinger SDK.
    """

    def __init__(self, lib_path: str = "libzkfp.so", db_path: str = DB_PATH):
        """
        Initialize the fingerprint manager.

        Args:
            lib_path: Path to the ZKFinger SDK library
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        self.sdk = None
        self.device = None
        self.fp_image_size = 0
        self.match_threshold = DEFAULT_MATCH_THRESHOLD

        # Initialize the SDK and open the device
        try:
            self.sdk = zkfinger.ZKFingerSDK(lib_path=lib_path)
            self._init_device()
            self._init_database()
        except zkfinger.ZKFingerError as e:
            logger.error(f"Failed to initialize SDK: {e}")
            raise

    def _init_device(self):
        """Initialize the fingerprint device and get parameters."""
        try:
            device_count = self.sdk.get_device_count()
            if device_count == 0:
                raise zkfinger.ZKFingerError("No fingerprint devices found.")

            logger.info(f"Found {device_count} fingerprint device(s)")
            self.device = self.sdk.open_device(0)

            # Get device parameters
            width = self.device.get_parameter(1)  # Parameter 1: Width
            height = self.device.get_parameter(2)  # Parameter 2: Height
            self.fp_image_size = width * height

            # Output device information
            logger.info(f"Device opened successfully")
            logger.info(f"Image dimensions: {width}x{height} ({self.fp_image_size} bytes)")

            # Set the 1:1 verification threshold
            self._set_match_threshold(self.match_threshold)

        except zkfinger.ZKFingerError as e:
            logger.error(f"Device initialization failed: {e}")
            if self.sdk:
                self.sdk.lib.ZKFPM_Terminate()
            raise

    def _set_match_threshold(self, threshold: int):
        """
        Set the fingerprint matching threshold.

        Args:
            threshold: Matching threshold (0-100)
        """
        try:
            # Parameter FP_THRESHOLD_CODE (1) as per API.md
            self.device.set_parameter(1, threshold)
            self.match_threshold = threshold
            logger.debug(f"Match threshold set to {threshold}")
        except zkfinger.ZKFingerError as e:
            logger.warning(f"Could not set match threshold: {e}")

    def _init_database(self):
        """Initialize the SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create users table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    fingerprint BLOB NOT NULL,
                    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    def _acquire_fingerprint(self, message: str = "Place your finger on the scanner") -> Tuple[bytes, bytes]:
        """
        Acquire a fingerprint from the device with retries and proper error handling.

        Args:
            message: Message to display to the user

        Returns:
            Tuple of (image_data, template_data)

        Raises:
            zkfinger.ZKFingerError: If fingerprint acquisition fails after all retries
        """
        click.echo(f"\n{message}...")

        # Allow the sensor to settle
        time.sleep(SETTLE_TIME)

        start_time = time.time()
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Try to acquire the fingerprint
                image_data, template_data = self.device.acquire_fingerprint(
                    fp_image_size=self.fp_image_size,
                    fp_template_size=TEMPLATE_SIZE,
                    max_retries=3,
                    retry_delay=0
                )

                duration = time.time() - start_time
                logger.info(f"Fingerprint acquired on attempt {attempt} (took {duration:.2f}s)")
                click.echo(f"Fingerprint acquired successfully!")

                return image_data, template_data

            except zkfinger.ZKFingerError as e:
                if "error -8" in str(e):  # Failed to capture image
                    if attempt < MAX_RETRIES:
                        click.echo(f"Attempt {attempt}/{MAX_RETRIES}: Waiting for finger placement... ")
                        time.sleep(ACQUISITION_DELAY)
                    else:
                        raise zkfinger.ZKFingerError("Failed to capture fingerprint after maximum retries")
                else:
                    raise  # Re-raise other errors

        # This should not be reached due to the raise in the loop
        raise zkfinger.ZKFingerError("Failed to acquire fingerprint")

    def register_fingerprint(self, name: str, num_samples: int = DEFAULT_SAMPLES) -> bool:
        """
        Register a new fingerprint by acquiring multiple samples and storing in the database.

        Args:
            name: User name to associate with the fingerprint
            num_samples: Number of samples to capture for registration

        Returns:
            True if registration was successful, False otherwise
        """
        if not name:
            click.echo("Error: User name cannot be empty")
            return False

        # Check if user already exists
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE name = ?", (name,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            if not click.confirm(f"User '{name}' already exists. Do you want to overwrite?"):
                return False

        click.echo(f"\nRegistering fingerprint for user: {name}")
        click.echo(f"Please provide {num_samples} fingerprint samples")

        templates = []

        # Collect samples
        for i in range(num_samples):
            try:
                if i > 0:
                    click.echo("Please remove your finger")
                    time.sleep(1)
                    click.confirm(f"Ready for sample {i+1}/{num_samples}?", default=True)

                _, template = self._acquire_fingerprint(f"[Sample {i+1}/{num_samples}] Place your finger on the scanner")
                templates.append(template)

                # Verify that this sample matches previous ones if we have any
                if i > 0:
                    # Use the SDK's DBMatch function to compare templates
                    try:
                        # Create a temporary DB for matching
                        db_cache = self.sdk.lib.ZKFPM_DBInit()
                        if not db_cache:
                            raise zkfinger.ZKFingerError("Failed to create temporary database for matching")

                        # Set up C types for the comparison
                        t1 = (ctypes.c_ubyte * len(templates[i-1]))(*templates[i-1])
                        t2 = (ctypes.c_ubyte * len(template))(*template)

                        # Call DBMatch
                        score = self.sdk.lib.ZKFPM_DBMatch(
                            db_cache,
                            ctypes.cast(t1, ctypes.POINTER(ctypes.c_ubyte)),
                            len(templates[i-1]),
                            ctypes.cast(t2, ctypes.POINTER(ctypes.c_ubyte)),
                            len(template)
                        )

                        # Free the temporary DB
                        self.sdk.lib.ZKFPM_DBFree(db_cache)

                        if score < self.match_threshold:
                            click.echo(f"Sample {i+1} does not match previous samples (score: {score})")
                            click.echo("Please try again from the beginning")
                            return False
                        else:
                            click.echo(f"Sample {i+1} matches previous samples (score: {score})")

                    except Exception as e:
                        logger.error(f"Error during template matching: {e}")
                        click.echo("Error during fingerprint matching. Please try again.")
                        return False

            except zkfinger.ZKFingerError as e:
                logger.error(f"Error acquiring fingerprint: {e}")
                click.echo(f"Error acquiring fingerprint: {e}")
                return False

        # Create merged template from all samples
        try:
            # Create a temporary DB for merging
            db_cache = self.sdk.lib.ZKFPM_DBInit()
            if not db_cache:
                raise zkfinger.ZKFingerError("Failed to create temporary database for merging")

            # Convert templates to C types
            c_templates = []
            for template in templates:
                c_template = (ctypes.c_ubyte * len(template))(*template)
                c_templates.append(c_template)

            # Prepare merged template buffer
            merged_template = (ctypes.c_ubyte * TEMPLATE_SIZE)()
            merged_size = ctypes.c_uint(TEMPLATE_SIZE)

            # Call DBMerge
            ret = self.sdk.lib.ZKFPM_DBMerge(
                db_cache,
                ctypes.cast(c_templates[0], ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.cast(c_templates[1], ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.cast(c_templates[2] if len(c_templates) > 2 else c_templates[1], ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.cast(merged_template, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(merged_size)
            )

            # Free the temporary DB
            self.sdk.lib.ZKFPM_DBFree(db_cache)

            if ret != 0:  # ZKFP_ERR_OK
                raise zkfinger.ZKFingerError(f"Template merge failed with error code: {ret}")

            # Convert to bytes for storage
            final_template = bytes(merged_template[:merged_size.value])

        except Exception as e:
            logger.error(f"Error creating merged template: {e}")
            click.echo(f"Error creating merged template: {e}")
            return False

        # Store the template in the database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO users (name, fingerprint) VALUES (?, ?)",
                (name, final_template)
            )
            conn.commit()
            conn.close()

            logger.info(f"User '{name}' registered successfully")
            click.echo(f"\nUser '{name}' registered successfully!")
            return True

        except sqlite3.Error as e:
            logger.error(f"Database error during registration: {e}")
            click.echo(f"Database error: {e}")
            return False

    def verify_fingerprint(self, name: str) -> bool:
        """
        Verify a fingerprint against a specific user's template.

        Args:
            name: User name to verify against

        Returns:
            True if verification successful, False otherwise
        """
        if not name:
            click.echo("Error: User name cannot be empty")
            return False

        # Retrieve the stored template
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT fingerprint FROM users WHERE name = ?", (name,))
            result = cursor.fetchone()
            conn.close()

            if not result:
                click.echo(f"User '{name}' not found in the database")
                return False

            stored_template = result[0]

        except sqlite3.Error as e:
            logger.error(f"Database error during verification: {e}")
            click.echo(f"Database error: {e}")
            return False

        # Acquire a new fingerprint for verification
        try:
            click.echo(f"\nVerifying fingerprint for user: {name}")
            _, new_template = self._acquire_fingerprint("Place your finger on the scanner for verification")

            # Create a temporary DB for matching
            db_cache = self.sdk.lib.ZKFPM_DBInit()
            if not db_cache:
                raise zkfinger.ZKFingerError("Failed to create temporary database for matching")

            # Convert templates to C types
            c_stored = (ctypes.c_ubyte * len(stored_template))(*stored_template)
            c_new = (ctypes.c_ubyte * len(new_template))(*new_template)

            # Call DBMatch
            score = self.sdk.lib.ZKFPM_DBMatch(
                db_cache,
                ctypes.cast(c_stored, ctypes.POINTER(ctypes.c_ubyte)),
                len(stored_template),
                ctypes.cast(c_new, ctypes.POINTER(ctypes.c_ubyte)),
                len(new_template)
            )

            # Free the temporary DB
            self.sdk.lib.ZKFPM_DBFree(db_cache)

            if score >= self.match_threshold:
                logger.info(f"Verification successful for user '{name}' (score: {score})")
                click.echo(f"\nVerification successful! Fingerprint matches user '{name}'")
                click.echo(f"Match score: {score} (threshold: {self.match_threshold})")
                return True
            else:
                logger.info(f"Verification failed for user '{name}' (score: {score})")
                click.echo(f"\nVerification failed! Fingerprint does not match user '{name}'")
                click.echo(f"Match score: {score} (threshold: {self.match_threshold})")
                return False

        except zkfinger.ZKFingerError as e:
            logger.error(f"Error during verification: {e}")
            click.echo(f"Error during verification: {e}")
            return False

    def identify_fingerprint(self) -> Optional[str]:
        """
        Identify a fingerprint against all registered templates.

        Returns:
            User name if identification successful, None otherwise
        """
        # Get all registered templates
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name, fingerprint FROM users")
            users = cursor.fetchall()
            conn.close()

            if not users:
                click.echo("No users registered in the database")
                return None

            logger.info(f"Attempting identification against {len(users)} registered users")

        except sqlite3.Error as e:
            logger.error(f"Database error during identification: {e}")
            click.echo(f"Database error: {e}")
            return None

        # Acquire a fingerprint for identification
        try:
            click.echo("\nIdentifying fingerprint...")
            _, new_template = self._acquire_fingerprint("Place your finger on the scanner for identification")

            # Create a temporary DB for matching
            db_cache = self.sdk.lib.ZKFPM_DBInit()
            if not db_cache:
                raise zkfinger.ZKFingerError("Failed to create temporary database for matching")

            # Check against each stored template
            best_match = None
            best_score = 0

            for name, stored_template in users:
                # Convert templates to C types
                c_stored = (ctypes.c_ubyte * len(stored_template))(*stored_template)
                c_new = (ctypes.c_ubyte * len(new_template))(*new_template)

                # Call DBMatch
                score = self.sdk.lib.ZKFPM_DBMatch(
                    db_cache,
                    ctypes.cast(c_stored, ctypes.POINTER(ctypes.c_ubyte)),
                    len(stored_template),
                    ctypes.cast(c_new, ctypes.POINTER(ctypes.c_ubyte)),
                    len(new_template)
                )

                logger.debug(f"Match score for user '{name}': {score}")

                if score > best_score:
                    best_score = score
                    best_match = name

            # Free the temporary DB
            self.sdk.lib.ZKFPM_DBFree(db_cache)

            if best_score >= self.match_threshold:
                logger.info(f"Identification successful: matched user '{best_match}' (score: {best_score})")
                click.echo(f"\nIdentification successful!")
                click.echo(f"Matched user: {best_match}")
                click.echo(f"Match score: {best_score} (threshold: {self.match_threshold})")
                return best_match
            else:
                logger.info(f"Identification failed (best score: {best_score})")
                click.echo(f"\nIdentification failed! No matching fingerprint found")
                if best_match:
                    click.echo(f"Best match: {best_match} (score: {best_score}, threshold: {self.match_threshold})")
                return None

        except zkfinger.ZKFingerError as e:
            logger.error(f"Error during identification: {e}")
            click.echo(f"Error during identification: {e}")
            return None

    def list_users(self) -> List[Dict[str, Any]]:
        """
        List all registered users.

        Returns:
            List of user dictionaries with 'id', 'name', and 'date_added' fields
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, date_added FROM users ORDER BY name")
            users = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return users
        except sqlite3.Error as e:
            logger.error(f"Database error while listing users: {e}")
            click.echo(f"Database error: {e}")
            return []

    def delete_user(self, name: str) -> bool:
        """
        Delete a user from the database.

        Args:
            name: User name to delete

        Returns:
            True if deletion successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE name = ?", (name,))
            user = cursor.fetchone()

            if not user:
                click.echo(f"User '{name}' not found")
                return False

            cursor.execute("DELETE FROM users WHERE name = ?", (name,))
            conn.commit()
            conn.close()

            logger.info(f"User '{name}' deleted successfully")
            click.echo(f"User '{name}' deleted successfully")
            return True

        except sqlite3.Error as e:
            logger.error(f"Database error during user deletion: {e}")
            click.echo(f"Database error: {e}")
            return False

    def set_threshold(self, threshold: int) -> bool:
        """
        Set the fingerprint matching threshold.

        Args:
            threshold: Matching threshold (0-100)

        Returns:
            True if successful, False otherwise
        """
        if threshold < 0 or threshold > 100:
            click.echo("Threshold must be between 0 and 100")
            return False

        try:
            self._set_match_threshold(threshold)
            click.echo(f"Match threshold set to {threshold}")
            return True
        except zkfinger.ZKFingerError as e:
            logger.error(f"Failed to set threshold: {e}")
            click.echo(f"Failed to set threshold: {e}")
            return False

    def cleanup(self):
        """Close the device and cleanup resources."""
        if self.device:
            try:
                self.device.close()
                logger.info("Device closed")
            except zkfinger.ZKFingerError as e:
                logger.error(f"Error closing device: {e}")

        if self.sdk:
            try:
                self.sdk.lib.ZKFPM_Terminate()
                logger.info("SDK terminated")
            except Exception as e:
                logger.error(f"Error terminating SDK: {e}")


# Click CLI commands

@click.group(invoke_without_command=True)
@click.option('--lib-path', default="libzkfp.so", help="Path to the ZKFinger SDK library")
@click.option('--db-path', default=DB_PATH, help="Path to the SQLite database")
@click.option('--debug/--no-debug', default=False, help="Enable debug logging")
@click.pass_context
def cli(ctx, lib_path, db_path, debug):
    """
    Fingerprint authentication tool for ZKTeco Live20R scanners
    """
    # Set debug level if requested
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize the fingerprint manager
    try:
        ctx.obj = FingerprintManager(lib_path=lib_path, db_path=db_path)
    except Exception as e:
        click.echo(f"Error initializing fingerprint manager: {e}")
        ctx.exit(1)

    # If no subcommand is provided, run the interactive menu
    if ctx.invoked_subcommand is None:
        try:
            interactive_menu(ctx.obj)
        finally:
            ctx.obj.cleanup()


@cli.command()
@click.option('--name', required=True, help="User name to associate with the fingerprint")
@click.option('--samples', default=DEFAULT_SAMPLES, help="Number of samples to capture")
@click.pass_obj
def register(fp_manager, name, samples):
    """Register a new fingerprint"""
    try:
        fp_manager.register_fingerprint(name, num_samples=samples)
    except Exception as e:
        click.echo(f"Error during registration: {e}")
    finally:
        fp_manager.cleanup()


@cli.command()
@click.option('--name', required=True, help="User name to verify against")
@click.pass_obj
def verify(fp_manager, name):
    """Verify a fingerprint against a specific user"""
    try:
        fp_manager.verify_fingerprint(name)
    except Exception as e:
        click.echo(f"Error during verification: {e}")
    finally:
        fp_manager.cleanup()


@cli.command()
@click.pass_obj
def identify(fp_manager):
    """Identify a fingerprint against all registered users"""
    try:
        fp_manager.identify_fingerprint()
    except Exception as e:
        click.echo(f"Error during identification: {e}")
    finally:
        fp_manager.cleanup()


@cli.command()
@click.pass_obj
def list(fp_manager):
    """List all registered users"""
    try:
        users = fp_manager.list_users()
        if users:
            click.echo("\nRegistered users:")
            for user in users:
                click.echo(f"- {user['name']} (ID: {user['id']}, Added: {user['date_added']})")
        else:
            click.echo("No users registered")
    except Exception as e:
        click.echo(f"Error listing users: {e}")
    finally:
        fp_manager.cleanup()


@cli.command()
@click.option('--name', required=True, help="User name to delete")
@click.pass_obj
def delete(fp_manager, name):
    """Delete a user from the database"""
    try:
        fp_manager.delete_user(name)
    except Exception as e:
        click.echo(f"Error deleting user: {e}")
    finally:
        fp_manager.cleanup()


@cli.command()
@click.option('--value', type=int, required=True, help="Threshold value (0-100)")
@click.pass_obj
def threshold(fp_manager, value):
    """Set the fingerprint matching threshold"""
    try:
        fp_manager.set_threshold(value)
    except Exception as e:
        click.echo(f"Error setting threshold: {e}")
    finally:
        fp_manager.cleanup()


def interactive_menu(fp_manager):
    """Interactive menu for the fingerprint tool"""
    while True:
        click.clear()
        click.echo("\nFingerprint Authentication Tool")
        click.echo("============================")
        click.echo("1. Register fingerprint")
        click.echo("2. Verify fingerprint")
        click.echo("3. Identify fingerprint")
        click.echo("4. List registered users")
        click.echo("5. Delete user")
        click.echo("6. Set matching threshold")
        click.echo("7. Exit")

        choice = click.prompt("Select an option", type=int, default=1)

        if choice == 1:
            name = click.prompt("Enter user name")
            samples = click.prompt("Enter number of samples to capture", type=int, default=DEFAULT_SAMPLES)
            fp_manager.register_fingerprint(name, num_samples=samples)
            click.pause()

        elif choice == 2:
            name = click.prompt("Enter user name to verify")
            fp_manager.verify_fingerprint(name)
            click.pause()

        elif choice == 3:
            fp_manager.identify_fingerprint()
            click.pause()

        elif choice == 4:
            users = fp_manager.list_users()
            if users:
                click.echo("\nRegistered users:")
                for user in users:
                    click.echo(f"- {user['name']} (ID: {user['id']}, Added: {user['date_added']})")
            else:
                click.echo("No users registered")
            click.pause()

        elif choice == 5:
            name = click.prompt("Enter user name to delete")
            if click.confirm(f"Are you sure you want to delete user '{name}'?"):
                fp_manager.delete_user(name)
            click.pause()

        elif choice == 6:
            current = fp_manager.match_threshold
            value = click.prompt(f"Enter new threshold (current: {current}, range: 0-100)", type=int)
            fp_manager.set_threshold(value)
            click.pause()

        elif choice == 7:
            click.echo("Exiting...")
            break

        else:
            click.echo("Invalid option")
            click.pause()


if __name__ == "__main__":
    # Import ctypes for SDK functions that require it
    import ctypes

    # Run the CLI
    cli()
