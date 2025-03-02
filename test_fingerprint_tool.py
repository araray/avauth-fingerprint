#!/usr/bin/env python3
"""
Test suite for the Enhanced Fingerprint Authentication Tool.

This module contains both unit tests and functional tests to verify the
correct behavior of the fingerprint tool and the ZKFinger SDK wrapper.

Usage:
    python -m unittest test_fingerprint_tool.py

Author: Araray
Date: 2025-03-02
"""

import os
import sys
import time
import unittest
import sqlite3
import tempfile
import logging
from unittest import mock
from contextlib import contextmanager

# Import the modules to test
# Make sure these modules are in your PYTHONPATH
try:
    # First try to import directly (if in the same directory)
    import zkfinger_enhanced as zkf
    from improved_fingerprint_tool import FingerprintManager
except ImportError:
    # Add parent directory to sys.path if needed
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import zkfinger_enhanced as zkf
    from improved_fingerprint_tool import FingerprintManager


# Create a mock logger to avoid polluting test output
logging.getLogger().setLevel(logging.CRITICAL)


class MockSDK:
    """Mock ZKFingerSDK for testing without actual hardware."""

    def __init__(self, lib_path=None):
        """Initialize the mock SDK."""
        self.terminated = False
        self.device_count = 1  # Simulate one connected device
        self.open_devices = []
        self.db_caches = []

        # Mock library
        self.lib = mock.MagicMock()
        self.lib.ZKFPM_Init.return_value = 0  # Success
        self.lib.ZKFPM_Terminate.return_value = 0  # Success
        self.lib.ZKFPM_GetDeviceCount.return_value = self.device_count

        # Setup the DBInit function to create unique handles
        self.db_cache_counter = 0
        def mock_db_init():
            self.db_cache_counter += 1
            return self.db_cache_counter
        self.lib.ZKFPM_DBInit.side_effect = mock_db_init

        # Setup mock DB functions
        self.lib.ZKFPM_DBFree.return_value = 0  # Success
        self.lib.ZKFPM_DBAdd.return_value = 0  # Success
        self.lib.ZKFPM_DBDel.return_value = 0  # Success
        self.lib.ZKFPM_DBClear.return_value = 0  # Success

        # Mock templates will contain the user ID for easy testing
        self.templates = {}  # tid -> template

        # Setup DB match function
        def mock_db_match(db_cache, template1, len1, template2, len2):
            if template1 and template2:
                # Convert to bytes for comparison
                t1 = bytes(template1[:len1])
                t2 = bytes(template2[:len2])
                # Return a match score based on similarity
                if t1 == t2:
                    return 100  # Perfect match
                elif t1[:len(t1)//2] == t2[:len(t2)//2]:
                    return 70  # Partial match
                else:
                    return 30  # Poor match
            return 0  # No match

        self.lib.ZKFPM_DBMatch.side_effect = mock_db_match

        # Setup DB identify function
        def mock_db_identify(db_cache, template, len_template, tid_ptr, score_ptr):
            t = bytes(template[:len_template])
            best_score = 0
            best_tid = 0

            for tid, stored_template in self.templates.items():
                if t == stored_template:
                    score = 100
                elif t[:len(t)//2] == stored_template[:len(stored_template)//2]:
                    score = 70
                else:
                    score = 30

                if score > best_score:
                    best_score = score
                    best_tid = tid

            if best_score >= 60:  # Threshold
                # Set the output parameters
                import ctypes
                ctypes.memmove(tid_ptr, ctypes.byref(ctypes.c_uint(best_tid)), 4)
                ctypes.memmove(score_ptr, ctypes.byref(ctypes.c_uint(best_score)), 4)
                return 0  # Success
            return -1  # No match

        self.lib.ZKFPM_DBIdentify.side_effect = mock_db_identify

        # Setup DB count function
        def mock_db_count(db_cache, count_ptr):
            import ctypes
            ctypes.memmove(count_ptr, ctypes.byref(ctypes.c_uint(len(self.templates))), 4)
            return 0  # Success

        self.lib.ZKFPM_DBCount.side_effect = mock_db_count

        # Setup DB merge function
        def mock_db_merge(db_cache, t1, t2, t3, merged, size_ptr):
            import ctypes
            # Create a merged template (just use t1 for simplicity)
            t1_bytes = bytes(t1[:100])  # Use first 100 bytes
            # Copy to output buffer
            ctypes.memmove(merged, t1, len(t1_bytes))
            # Set size
            ctypes.memmove(size_ptr, ctypes.byref(ctypes.c_uint(len(t1_bytes))), 4)
            return 0  # Success

        self.lib.ZKFPM_DBMerge.side_effect = mock_db_merge

    def get_device_count(self):
        """Get the number of connected devices."""
        return self.device_count

    def open_device(self, index):
        """Open a mock fingerprint device."""
        if index >= self.device_count:
            raise zkf.ZKFingerError(f"No device at index {index}")

        handle = index + 1  # Use index+1 as handle to avoid 0
        device = MockDevice(self, handle, index)
        self.open_devices.append(device)
        return device

    def terminate(self):
        """Terminate the mock SDK."""
        self.terminated = True
        for device in list(self.open_devices):
            device.close()
        self.open_devices = []


class MockDevice:
    """Mock fingerprint device for testing."""

    def __init__(self, sdk, handle, index):
        """Initialize the mock device."""
        self.sdk = sdk
        self.handle = handle
        self.index = index
        self.closed = False
        self.width = 300
        self.height = 400
        self.image_size = self.width * self.height

        # Sample fingerprint templates for testing
        self.sample_templates = {
            "user1": b'TEMPLATE_USER1' + b'\x00' * 100,
            "user2": b'TEMPLATE_USER2' + b'\x00' * 100,
            "user3": b'TEMPLATE_USER3' + b'\x00' * 100,
        }

        # Setup mock functions
        sdk.lib.ZKFPM_CloseDevice.return_value = 0  # Success

        # Mock the acquire fingerprint function
        def mock_acquire_fingerprint(device_handle, fp_image, fp_image_size, fp_template, template_size_ptr):
            import ctypes
            import time

            # Simulate device behavior
            if self.closed:
                return -7  # Invalid handle

            # Simulate a delay
            time.sleep(0.1)

            # Get the sample template (use a default one if no specific one is set)
            template = getattr(self, 'current_template', self.sample_templates["user1"])

            # Copy template to output buffer
            template_size = min(len(template), template_size_ptr.contents.value)
            ctypes.memmove(fp_template, template, template_size)

            # Set actual template size
            template_size_ptr.contents.value = template_size

            # Create a dummy image (just zeros)
            dummy_image = bytes([0] * min(fp_image_size, 1000))
            ctypes.memmove(fp_image, dummy_image, len(dummy_image))

            return 0  # Success

        sdk.lib.ZKFPM_AcquireFingerprint.side_effect = mock_acquire_fingerprint

        # Mock parameter functions
        def mock_get_parameters(device_handle, param_code, param_value, param_size_ptr):
            import ctypes

            if param_code == 1:  # Width
                value = self.width
            elif param_code == 2:  # Height
                value = self.height
            else:
                value = 0

            # Convert to bytes and copy to output buffer
            value_bytes = value.to_bytes(4, byteorder='little')
            size = min(len(value_bytes), param_size_ptr.contents.value)
            ctypes.memmove(param_value, value_bytes, size)

            # Set actual size
            param_size_ptr.contents.value = size

            return 0  # Success

        sdk.lib.ZKFPM_GetParameters.side_effect = mock_get_parameters

        def mock_set_parameters(device_handle, param_code, param_value, param_size):
            # Just return success for all parameter sets
            return 0

        sdk.lib.ZKFPM_SetParameters.side_effect = mock_set_parameters

    def close(self):
        """Close the mock device."""
        if not self.closed:
            self.closed = True
            if self in self.sdk.open_devices:
                self.sdk.open_devices.remove(self)

    def set_template(self, template):
        """Set the template that will be returned by acquire_fingerprint."""
        self.current_template = template

    def acquire_fingerprint(self, fp_image_size=None, fp_template_size=2048, max_retries=10, retry_delay=0.1):
        """Mock implementation of acquire_fingerprint."""
        if self.closed:
            raise zkf.ZKFingerError("Device is closed")

        if fp_image_size is None:
            fp_image_size = self.image_size

        import ctypes

        # Allocate buffers
        fp_image = (ctypes.c_ubyte * fp_image_size)()
        fp_template = (ctypes.c_ubyte * fp_template_size)()
        template_size = ctypes.c_uint(fp_template_size)

        # Call the mocked function
        ret = self.sdk.lib.ZKFPM_AcquireFingerprint(
            self.handle,
            ctypes.cast(fp_image, ctypes.POINTER(ctypes.c_ubyte)),
            fp_image_size,
            ctypes.cast(fp_template, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(template_size)
        )

        if ret != 0:
            raise zkf.ZKFingerError("Fingerprint acquisition failed", ret)

        # Convert to bytes
        image_data = bytes(fp_image)
        template_data = bytes(fp_template[:template_size.value])

        return image_data, template_data

    def get_parameter(self, param_code):
        """Mock implementation of get_parameter."""
        if self.closed:
            raise zkf.ZKFingerError("Device is closed")

        import ctypes

        # Allocate buffer for parameter value (4 bytes for integer)
        param_value = (ctypes.c_ubyte * 4)()
        param_size = ctypes.c_uint(4)

        # Call the mocked function
        ret = self.sdk.lib.ZKFPM_GetParameters(
            self.handle,
            param_code,
            param_value,
            ctypes.byref(param_size)
        )

        if ret != 0:
            raise zkf.ZKFingerError(f"Failed to get parameter {param_code}", ret)

        # Convert to int
        value = int.from_bytes(bytes(param_value[:param_size.value]), byteorder='little')

        return value

    def set_parameter(self, param_code, value):
        """Mock implementation of set_parameter."""
        if self.closed:
            raise zkf.ZKFingerError("Device is closed")

        import ctypes

        # Convert value to bytes
        value_bytes = value.to_bytes(4, byteorder='little')

        # Allocate buffer and copy value
        param_value = (ctypes.c_ubyte * 4)(*value_bytes)

        # Call the mocked function
        ret = self.sdk.lib.ZKFPM_SetParameters(
            self.handle,
            param_code,
            param_value,
            4
        )

        if ret != 0:
            raise zkf.ZKFingerError(f"Failed to set parameter {param_code} to {value}", ret)

        return True


@contextmanager
def temp_database():
    """Context manager that creates a temporary SQLite database."""
    fd, path = tempfile.mkstemp(suffix='.db')
    try:
        os.close(fd)
        yield path
    finally:
        os.unlink(path)


class TestZKFingerSDK(unittest.TestCase):
    """Unit tests for the ZKFinger SDK wrapper."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock SDK
        self.sdk = MockSDK()

        # Mock the zkf.ZKFingerSDK class to return our mock
        patcher = mock.patch('zkfinger_enhanced.ZKFingerSDK', return_value=self.sdk)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_init_terminate(self):
        """Test SDK initialization and termination."""
        # Test initialization
        sdk = zkf.ZKFingerSDK()
        self.assertFalse(sdk.terminated)

        # Test termination
        sdk.terminate()
        self.assertTrue(sdk.terminated)

    def test_get_device_count(self):
        """Test getting device count."""
        sdk = zkf.ZKFingerSDK()
        count = sdk.get_device_count()
        self.assertEqual(count, 1)

    def test_open_close_device(self):
        """Test opening and closing a device."""
        sdk = zkf.ZKFingerSDK()

        # Open device
        device = sdk.open_device(0)
        self.assertIsNotNone(device)
        self.assertEqual(len(sdk.open_devices), 1)

        # Close device
        device.close()
        self.assertEqual(len(sdk.open_devices), 0)
        self.assertTrue(device.closed)

    def test_acquire_fingerprint(self):
        """Test fingerprint acquisition."""
        sdk = zkf.ZKFingerSDK()
        device = sdk.open_device(0)

        # Set a specific template to return
        device.set_template(device.sample_templates["user2"])

        # Acquire fingerprint
        image, template = device.acquire_fingerprint()

        # Verify the returned template
        self.assertEqual(template[:13], b'TEMPLATE_USER2')

        # Clean up
        device.close()

    def test_db_operations(self):
        """Test database operations."""
        sdk = zkf.ZKFingerSDK()

        # Initialize DB cache
        db_cache = sdk.init_db_cache()
        self.assertIsNotNone(db_cache)

        # Add a template
        template = b'TEST_TEMPLATE' + b'\x00' * 100
        sdk.db_add(db_cache, 1, template)
        sdk.templates[1] = template  # Add to mock templates

        # Get count
        count = sdk.db_count(db_cache)
        self.assertEqual(count, 1)

        # Match templates
        score = sdk.db_match(db_cache, template, template)
        self.assertEqual(score, 100)  # Perfect match

        # Different templates should have lower score
        different_template = b'DIFF_TEMPLATE' + b'\x00' * 100
        score = sdk.db_match(db_cache, template, different_template)
        self.assertLess(score, 100)

        # Clean up
        sdk.free_db_cache(db_cache)


class TestFingerprintManager(unittest.TestCase):
    """Unit tests for the FingerprintManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock SDK
        self.mock_sdk = MockSDK()

        # Create a temporary database
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.close(self.db_fd)

        # Mock the zkf.ZKFingerSDK class
        self.sdk_patcher = mock.patch('zkfinger_enhanced.ZKFingerSDK', return_value=self.mock_sdk)
        self.addCleanup(self.sdk_patcher.stop)
        self.sdk_patcher.start()

        # Prepare sample templates
        self.sample_templates = {
            "user1": b'TEMPLATE_USER1' + b'\x00' * 100,
            "user2": b'TEMPLATE_USER2' + b'\x00' * 100,
            "user3": b'TEMPLATE_USER3' + b'\x00' * 100,
        }

    def tearDown(self):
        """Tear down test fixtures."""
        os.unlink(self.db_path)

    def test_init(self):
        """Test FingerprintManager initialization."""
        with mock.patch('improved_fingerprint_tool.zkfinger', zkf):
            manager = FingerprintManager(lib_path="dummy.so", db_path=self.db_path)
            self.assertIsNotNone(manager.sdk)
            self.assertIsNotNone(manager.device)
            manager.cleanup()

    def test_register_verify_identify(self):
        """Test fingerprint registration, verification, and identification."""
        with mock.patch('improved_fingerprint_tool.zkfinger', zkf):
            # Initialize manager
            manager = FingerprintManager(lib_path="dummy.so", db_path=self.db_path)

            # Setup mock to return specific templates
            def mock_acquire_fingerprint(message):
                if "user1" in getattr(manager, '_current_test_user', ''):
                    return (b'', self.sample_templates["user1"])
                elif "user2" in getattr(manager, '_current_test_user', ''):
                    return (b'', self.sample_templates["user2"])
                else:
                    return (b'', self.sample_templates["user3"])

            manager._acquire_fingerprint = mock_acquire_fingerprint

            # Test registration
            manager._current_test_user = "user1"
            result = manager.register_fingerprint("user1", num_samples=3)
            self.assertTrue(result)

            manager._current_test_user = "user2"
            result = manager.register_fingerprint("user2", num_samples=3)
            self.assertTrue(result)

            # Test verification
            manager._current_test_user = "user1"
            result = manager.verify_fingerprint("user1")
            self.assertTrue(result)

            # Test incorrect verification
            manager._current_test_user = "user2"
            result = manager.verify_fingerprint("user1")
            self.assertFalse(result)

            # Test identification
            manager._current_test_user = "user1"
            user = manager.identify_fingerprint()
            self.assertEqual(user, "user1")

            # Test unknown fingerprint
            manager._current_test_user = "unknown"
            user = manager.identify_fingerprint()
            self.assertIsNone(user)

            # Clean up
            manager.cleanup()

    def test_user_management(self):
        """Test user management operations."""
        with mock.patch('improved_fingerprint_tool.zkfinger', zkf):
            # Initialize manager
            manager = FingerprintManager(lib_path="dummy.so", db_path=self.db_path)

            # Setup mock to return specific templates
            def mock_acquire_fingerprint(message):
                return (b'', self.sample_templates["user1"])

            manager._acquire_fingerprint = mock_acquire_fingerprint

            # Register a user
            result = manager.register_fingerprint("test_user", num_samples=3)
            self.assertTrue(result)

            # List users
            users = manager.list_users()
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]['name'], "test_user")

            # Delete user
            result = manager.delete_user("test_user")
            self.assertTrue(result)

            # List users again (should be empty)
            users = manager.list_users()
            self.assertEqual(len(users), 0)

            # Clean up
            manager.cleanup()


class TestClickCommands(unittest.TestCase):
    """Functional tests for Click commands."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock SDK
        self.mock_sdk = MockSDK()

        # Create a temporary database
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.close(self.db_fd)

        # Mock the zkf.ZKFingerSDK class
        self.sdk_patcher = mock.patch('zkfinger_enhanced.ZKFingerSDK', return_value=self.mock_sdk)
        self.addCleanup(self.sdk_patcher.stop)
        self.sdk_patcher.start()

        # Mock click functions
        self.click_echo_patcher = mock.patch('click.echo')
        self.mock_click_echo = self.click_echo_patcher.start()
        self.addCleanup(self.click_echo_patcher.stop)

        self.click_confirm_patcher = mock.patch('click.confirm', return_value=True)
        self.click_confirm_patcher.start()
        self.addCleanup(self.click_confirm_patcher.stop)

        # Import click commands after patching
        import improved_fingerprint_tool
        self.cmds = improved_fingerprint_tool

        # Prepare a fingerprint manager for testing
        self.manager = self.cmds.FingerprintManager(lib_path="dummy.so", db_path=self.db_path)

        # Prepare sample templates
        self.sample_templates = {
            "user1": b'TEMPLATE_USER1' + b'\x00' * 100,
            "user2": b'TEMPLATE_USER2' + b'\x00' * 100,
            "user3": b'TEMPLATE_USER3' + b'\x00' * 100,
        }

    def tearDown(self):
        """Tear down test fixtures."""
        if hasattr(self, 'manager'):
            self.manager.cleanup()
        os.unlink(self.db_path)

    def test_register_command(self):
        """Test the register command."""
        with mock.patch('improved_fingerprint_tool.FingerprintManager', return_value=self.manager):
            # Setup mock to return specific templates
            def mock_acquire_fingerprint(message):
                return (b'', self.sample_templates["user1"])

            self.manager._acquire_fingerprint = mock_acquire_fingerprint

            # Run register command
            self.cmds.register(self.manager, "test_user", 3)

            # Verify user was registered
            users = self.manager.list_users()
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]['name'], "test_user")

    def test_verify_command(self):
        """Test the verify command."""
        with mock.patch('improved_fingerprint_tool.FingerprintManager', return_value=self.manager):
            # Setup mock to return specific templates
            def mock_acquire_fingerprint(message):
                return (b'', self.sample_templates["user1"])

            self.manager._acquire_fingerprint = mock_acquire_fingerprint

            # Register a user first
            self.manager.register_fingerprint("test_user", num_samples=3)

            # Run verify command
            self.cmds.verify(self.manager, "test_user")

            # Check echo calls
            self.mock_click_echo.assert_any_call(mock.ANY)  # Multiple calls, don't check specific message

    def test_identify_command(self):
        """Test the identify command."""
        with mock.patch('improved_fingerprint_tool.FingerprintManager', return_value=self.manager):
            # Setup mock to return specific templates
            def mock_acquire_fingerprint(message):
                return (b'', self.sample_templates["user1"])

            self.manager._acquire_fingerprint = mock_acquire_fingerprint

            # Register a user first
            self.manager.register_fingerprint("test_user", num_samples=3)

            # Run identify command
            self.cmds.identify(self.manager)

            # Check echo calls
            self.mock_click_echo.assert_any_call(mock.ANY)  # Multiple calls, don't check specific message

    def test_list_command(self):
        """Test the list command."""
        with mock.patch('improved_fingerprint_tool.FingerprintManager', return_value=self.manager):
            # Register a user first
            def mock_acquire_fingerprint(message):
                return (b'', self.sample_templates["user1"])

            self.manager._acquire_fingerprint = mock_acquire_fingerprint
            self.manager.register_fingerprint("test_user", num_samples=3)

            # Run list command
            self.cmds.list(self.manager)

            # Check echo calls
            self.mock_click_echo.assert_any_call(mock.ANY)  # Multiple calls, don't check specific message

    def test_delete_command(self):
        """Test the delete command."""
        with mock.patch('improved_fingerprint_tool.FingerprintManager', return_value=self.manager):
            # Register a user first
            def mock_acquire_fingerprint(message):
                return (b'', self.sample_templates["user1"])

            self.manager._acquire_fingerprint = mock_acquire_fingerprint
            self.manager.register_fingerprint("test_user", num_samples=3)

            # Run delete command
            self.cmds.delete(self.manager, "test_user")

            # Verify user was deleted
            users = self.manager.list_users()
            self.assertEqual(len(users), 0)


if __name__ == '__main__':
    unittest.main()
