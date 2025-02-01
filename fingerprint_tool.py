#!/usr/bin/env python3
"""
Fingerprint Tool using ZKFinger SDK and SQLite3 (Revised for Persistent Device Handling)
===========================================================================================

This tool allows you to register, verify, and identify fingerprints.
It uses the Python wrapper (zkfinger.py) for the ZKFinger C API and stores
fingerprint templates along with a user name in a SQLite3 database.

Revisions:
- The SDK is initialized and the device is opened only once at startup.
- The image buffer size is computed as width * height (parameters 1 and 2).
- Increased delays and retry counts in fingerprint acquisition.
- Improved user prompts and error handling.

Usage:
------
    LD_LIBRARY_PATH=$PWD/libs python3 fingerprint_tool.py

Menu options:
  1. Register fingerprint
  2. Verify fingerprint
  3. Identify fingerprint
  4. Exit

Author: Your Name
Date: 2025-02-01 (Revised 2025-02-01)
"""

import sqlite3
import sys
import time

import zkfinger  # Ensure that zkfinger.py (the Python wrapper) is accessible

DB_PATH = "fingerprints.db"


def init_db():
    """
    Initialize the SQLite database by creating the 'users' table if it doesn't exist.
    The table stores:
      - id: Primary key
      - name: Unique user name
      - fingerprint: Fingerprint template as a BLOB
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            fingerprint BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def match_templates(template1: bytes, template2: bytes, threshold: float = 0.9) -> bool:
    """
    Naively compares two fingerprint templates by checking the proportion of matching bytes.
    **WARNING:** This is a placeholder matching algorithm. In production, use a robust
    fingerprint matching algorithm.

    :param template1: First fingerprint template.
    :param template2: Second fingerprint template.
    :param threshold: Similarity threshold (0.0 to 1.0).
    :return: True if similarity is above the threshold, False otherwise.
    """
    if len(template1) != len(template2):
        return False

    matches = sum(1 for a, b in zip(template1, template2) if a == b)
    similarity = matches / len(template1)
    return similarity >= threshold


def capture_sample(device: zkfinger.FingerprintDevice, sample_num: int, fp_image_size: int) -> bytes:
    """
    Captures a single fingerprint sample using the open device.

    :param device: The open FingerprintDevice instance.
    :param sample_num: The current sample number (for display purposes).
    :param fp_image_size: The size (in bytes) of the image buffer.
    :return: The captured fingerprint template as bytes, or None if an error occurs.
    """
    print(f"[Sample {sample_num}] Please place your finger on the scanner and remain still...")
    try:
        # Acquire fingerprint (we ignore the image here)
        _, fp_template = device.acquire_fingerprint(fp_image_size=fp_image_size)
        print(f"[Sample {sample_num}] Fingerprint sample acquired successfully.")
        return fp_template
    except zkfinger.ZKFingerError as e:
        print(f"[Sample {sample_num}] Error acquiring fingerprint: {e}")
        return None


def register_fingerprint(device: zkfinger.FingerprintDevice, fp_image_size: int):
    """
    Registers a new fingerprint by acquiring multiple samples.
    All samples must match (using a naive comparison) before the fingerprint is stored in the database.
    """
    user_name = input("Enter user name: ").strip()
    if not user_name:
        print("User name cannot be empty.")
        return

    try:
        num_samples_input = input("Enter number of samples to capture (default 3): ").strip()
        num_samples = int(num_samples_input) if num_samples_input else 3
    except ValueError:
        print("Invalid number, defaulting to 3 samples.")
        num_samples = 3

    samples = []
    for i in range(num_samples):
        if i > 0:
            input(f"Please remove your finger and press Enter when ready for acquisition #{i + 1}...")
        sample = capture_sample(device, i + 1, fp_image_size)
        if sample is None:
            print(f"Acquisition failed for sample {i + 1}. Aborting registration.")
            return
        samples.append(sample)
        time.sleep(1)

    # Verify that all samples match using our naive comparison.
    ref_template = samples[0]
    all_match = True
    for idx, sample in enumerate(samples[1:], start=2):
        if not match_templates(ref_template, sample):
            print(f"Sample {idx} does not match the first sample.")
            all_match = False
            break

    if not all_match:
        print("Fingerprint samples did not match. Please try again.")
        return
    else:
        print("All fingerprint samples match. Registration successful.")

    # Store the reference template in the SQLite database.
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR REPLACE INTO users (name, fingerprint) VALUES (?, ?)",
                       (user_name, ref_template))
        conn.commit()
        print(f"User '{user_name}' registered successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


def verify_fingerprint(device: zkfinger.FingerprintDevice, fp_image_size: int):
    """
    Verifies a fingerprint for a given user by acquiring a new sample and comparing it
    to the stored template.
    """
    user_name = input("Enter user name to verify: ").strip()
    if not user_name:
        print("User name cannot be empty.")
        return

    # Retrieve the stored fingerprint from the database.
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT fingerprint FROM users WHERE name = ?", (user_name,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        print(f"User '{user_name}' not found in the database.")
        return

    stored_template = row[0]

    print("Please place your finger on the scanner for verification...")
    new_template = capture_sample(device, sample_num=1, fp_image_size=fp_image_size)
    if new_template is None:
        print("Verification failed due to capture error.")
        return

    if match_templates(stored_template, new_template):
        print(f"Verification successful. Fingerprint matches for user '{user_name}'.")
    else:
        print(f"Verification failed. Fingerprint does not match for user '{user_name}'.")


def identify_fingerprint(device: zkfinger.FingerprintDevice, fp_image_size: int):
    """
    Identifies a user by acquiring a fingerprint sample and comparing it against all
    registered templates in the database.
    """
    print("Please place your finger on the scanner for identification...")
    new_template = capture_sample(device, sample_num=1, fp_image_size=fp_image_size)
    if new_template is None:
        print("Identification failed due to capture error.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name, fingerprint FROM users")
    rows = cursor.fetchall()
    conn.close()

    identified_user = None
    for name, stored_template in rows:
        if match_templates(stored_template, new_template):
            identified_user = name
            break

    if identified_user:
        print(f"Fingerprint identified as user: {identified_user}")
    else:
        print("Fingerprint not recognized.")


def main():
    """Main menu loop for the fingerprint tool."""
    init_db()

    # Initialize the SDK and open the device once.
    try:
        sdk = zkfinger.ZKFingerSDK(lib_path="libzkfp.so")
    except zkfinger.ZKFingerError as e:
        print(f"Failed to initialize SDK: {e}")
        sys.exit(1)

    try:
        device = sdk.open_device(0)
    except zkfinger.ZKFingerError as e:
        print(f"Error opening device: {e}")
        sys.exit(1)

    # Retrieve image dimensions (parameter 1: width, parameter 2: height) and compute buffer size.
    try:
        width = device.get_parameter(1)
        height = device.get_parameter(2)
        fp_image_size = width * height
        print(f"Image dimensions: width={width}, height={height}. Computed buffer size: {fp_image_size} bytes.")
    except zkfinger.ZKFingerError as e:
        print(f"Could not get image dimensions, defaulting image buffer size to 1024: {e}")
        fp_image_size = 1024

    # Main loop.
    while True:
        print("\nFingerprint Tool Menu")
        print("1. Register fingerprint")
        print("2. Verify fingerprint")
        print("3. Identify fingerprint")
        print("4. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            register_fingerprint(device, fp_image_size)
        elif choice == "2":
            verify_fingerprint(device, fp_image_size)
        elif choice == "3":
            identify_fingerprint(device, fp_image_size)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please select again.")

    # Cleanup: close the device.
    try:
        device.close()
    except zkfinger.ZKFingerError as e:
        print(f"Error closing device: {e}")


if __name__ == "__main__":
    main()
