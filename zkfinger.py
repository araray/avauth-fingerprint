#!/usr/bin/env python3
"""
zkfinger.py

A Python API wrapper for the ZKFinger SDK using ctypes.
This module loads the ZKFinger shared library (DLL/.so), initializes the SDK,
and exposes high-level classes to interact with ZKFinger fingerprint scanners.

Revisions:
- Increased initial sensor settle delay and per-attempt delay in acquire_fingerprint.
- Changed default retry count to 50.
- Minor logging improvements.

Author: Araray Velho
Date: 2025-02-01 (Revised 2025-02-01)
"""

import ctypes
import platform
import time


class ZKFingerError(Exception):
    """Custom exception for errors raised by the ZKFinger SDK wrapper."""
    pass


class ZKFingerSDK:
    """
    Python wrapper for the ZKFinger SDK.

    This class initializes the SDK library and provides methods to enumerate
    and open fingerprint devices.
    """

    def __init__(self, lib_path: str = None):
        """
        Initializes the ZKFinger SDK.

        :param lib_path: Optional path to the shared library file.
                         If None, a default name is chosen based on the OS.
        :raises ZKFingerError: If the shared library cannot be loaded or if
                               initialization fails.
        """
        if lib_path is None:
            # Determine default library name based on the operating system.
            if platform.system() == 'Windows':
                lib_name = "zkfinger.dll"
            else:
                lib_name = "libzkfp.so"  # Adjust the name if needed.
            lib_path = lib_name

        # Attempt to load the shared library.
        try:
            self.lib = ctypes.CDLL(lib_path)
        except OSError as e:
            raise ZKFingerError(f"Could not load library '{lib_path}': {e}")

        # Set up the function prototypes for the SDK functions.
        self._setup_functions()

        # Initialize the SDK.
        ret = self.lib.ZKFPM_Init()
        if ret != 0:
            raise ZKFingerError(f"ZKFPM_Init failed with error code: {ret}")

    def _setup_functions(self):
        """
        Sets up the function prototypes for the SDK functions.
        """
        # int ZKFPM_Init(void);
        self.lib.ZKFPM_Init.restype = ctypes.c_int
        self.lib.ZKFPM_Init.argtypes = []

        # int ZKFPM_Terminate(void);
        self.lib.ZKFPM_Terminate.restype = ctypes.c_int
        self.lib.ZKFPM_Terminate.argtypes = []

        # int ZKFPM_GetDeviceCount(void);
        self.lib.ZKFPM_GetDeviceCount.restype = ctypes.c_int
        self.lib.ZKFPM_GetDeviceCount.argtypes = []

        # HANDLE ZKFPM_OpenDevice(int index);
        self.lib.ZKFPM_OpenDevice.restype = ctypes.c_void_p
        self.lib.ZKFPM_OpenDevice.argtypes = [ctypes.c_int]

        # int ZKFPM_CloseDevice(HANDLE hDevice);
        self.lib.ZKFPM_CloseDevice.restype = ctypes.c_int
        self.lib.ZKFPM_CloseDevice.argtypes = [ctypes.c_void_p]

        # int ZKFPM_SetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int cbParamValue);
        self.lib.ZKFPM_SetParameters.restype = ctypes.c_int
        self.lib.ZKFPM_SetParameters.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint
        ]

        # int ZKFPM_GetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int* cbParamValue);
        self.lib.ZKFPM_GetParameters.restype = ctypes.c_int
        self.lib.ZKFPM_GetParameters.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint)
        ]

        # int ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage,
        #                              unsigned char* fpTemplate, unsigned int* cbTemplate);
        self.lib.ZKFPM_AcquireFingerprint.restype = ctypes.c_int
        self.lib.ZKFPM_AcquireFingerprint.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint)
        ]

    def __del__(self):
        """
        Destructor: Terminates the SDK when the object is garbage-collected.
        """
        try:
            if hasattr(self, 'lib'):
                self.lib.ZKFPM_Terminate()
        except Exception:
            # Avoid raising exceptions during interpreter shutdown.
            pass

    def get_device_count(self) -> int:
        """
        Retrieves the number of connected fingerprint devices.

        :return: The device count (>=0).
        :raises ZKFingerError: If the function call fails (returns a negative value).
        """
        count = self.lib.ZKFPM_GetDeviceCount()
        if count < 0:
            raise ZKFingerError(f"ZKFPM_GetDeviceCount failed with error code: {count}")
        return count

    def open_device(self, index: int) -> "FingerprintDevice":
        """
        Opens the fingerprint device at the specified index.

        :param index: The device index.
        :return: A FingerprintDevice instance representing the opened device.
        :raises ZKFingerError: If opening the device fails.
        """
        handle = self.lib.ZKFPM_OpenDevice(index)
        if not handle:
            raise ZKFingerError(f"ZKFPM_OpenDevice failed to open device at index {index}")
        return FingerprintDevice(handle, self.lib)


class FingerprintDevice:
    """
    Represents an open fingerprint device.
    """

    def __init__(self, handle: ctypes.c_void_p, lib: ctypes.CDLL):
        """
        Initializes a FingerprintDevice instance.

        :param handle: Device handle returned by ZKFPM_OpenDevice.
        :param lib: Reference to the loaded shared library.
        """
        self.handle = handle
        self.lib = lib

    def close(self):
        """
        Closes the fingerprint device.

        :raises ZKFingerError: If closing the device fails.
        """
        if self.handle:
            ret = self.lib.ZKFPM_CloseDevice(self.handle)
            if ret != 0:
                raise ZKFingerError(f"ZKFPM_CloseDevice failed with error code: {ret}")
            self.handle = None

    def set_parameter(self, param_code: int, value: int):
        """
        Sets a parameter for the fingerprint device.

        **Note:** This method assumes that the parameter value is a 32-bit integer.

        :param param_code: The parameter code.
        :param value: The integer value to set.
        :raises ZKFingerError: If setting the parameter fails.
        """
        c_value = ctypes.c_int(value)
        ret = self.lib.ZKFPM_SetParameters(
            self.handle,
            param_code,
            ctypes.cast(ctypes.byref(c_value), ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.sizeof(c_value)
        )
        if ret != 0:
            raise ZKFingerError(f"ZKFPM_SetParameters failed with error code: {ret}")

    def get_parameter(self, param_code: int) -> int:
        """
        Retrieves a parameter from the fingerprint device.

        **Note:** This method assumes that the parameter is a 32-bit integer.

        :param param_code: The parameter code.
        :return: The parameter value.
        :raises ZKFingerError: If retrieving the parameter fails.
        """
        c_value = ctypes.c_int(0)
        buf_size = ctypes.c_uint(ctypes.sizeof(c_value))
        ret = self.lib.ZKFPM_GetParameters(
            self.handle,
            param_code,
            ctypes.cast(ctypes.byref(c_value), ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(buf_size)
        )
        if ret != 0:
            raise ZKFingerError(f"ZKFPM_GetParameters failed with error code: {ret}")
        return c_value.value

    def acquire_fingerprint(self, fp_image_size: int, fp_template_size: int = 2048,
                              retries: int = 50, delay: float = 1.0) -> (bytes, bytes):
        """
        Captures a fingerprint template, retrying acquisition until success or timeout.

        :param fp_image_size: The size (in bytes) of the image buffer.
        :param fp_template_size: The size (in bytes) of the template buffer (default: 2048).
        :param retries: Number of retries before giving up.
        :param delay: Delay (in seconds) between retries.
        :return: A tuple (fp_image, fp_template)
        :raises ZKFingerError: If fingerprint acquisition fails after all retries.
        """
        # Allow sensor time to settle.
        print("Waiting for sensor to settle (5 seconds)...")
        time.sleep(5)

        for attempt in range(retries):
            # Allocate buffers for the image and the template.
            fp_image = (ctypes.c_ubyte * fp_image_size)()
            fp_template = (ctypes.c_ubyte * fp_template_size)()
            template_size = ctypes.c_uint(fp_template_size)

            # Explicitly cast the buffers to POINTER(c_ubyte)
            fp_image_ptr = ctypes.cast(fp_image, ctypes.POINTER(ctypes.c_ubyte))
            fp_template_ptr = ctypes.cast(fp_template, ctypes.POINTER(ctypes.c_ubyte))

            ret = self.lib.ZKFPM_AcquireFingerprint(
                self.handle,
                fp_image_ptr,
                fp_image_size,
                fp_template_ptr,
                ctypes.byref(template_size)
            )
            if ret == 0:
                # Successful acquisition: convert buffers to bytes.
                image_bytes = bytes(fp_image)
                template_bytes = bytes(fp_template)[:template_size.value]
                print(f"Fingerprint acquired on attempt {attempt + 1}.")
                return image_bytes, template_bytes
            else:
                if ret == -8:
                    print(f"Attempt {attempt + 1}/{retries}: Fingerprint acquisition returned error -8 (Failed to capture image), retrying in {delay:.1f}s...")
                else:
                    raise ZKFingerError(f"ZKFPM_AcquireFingerprint failed with error code: {ret}")
            time.sleep(delay)
        raise ZKFingerError("Fingerprint acquisition failed after multiple retries.")

    def __enter__(self) -> "FingerprintDevice":
        """Context manager entry: returns self."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager exit: closes the device."""
        self.close()
