#!/usr/bin/env python3
"""
Enhanced ZKFinger SDK Python Wrapper
====================================

A comprehensive Python wrapper for the ZKFinger SDK using ctypes.
This module loads the ZKFinger shared library, initializes the SDK,
and exposes high-level classes to interact with ZKFinger fingerprint scanners.

Key improvements over the original:
- More robust error handling
- Better memory management
- Support for database operations (ZKFPM_DBInit, ZKFPM_DBMatch, etc.)
- Full implementation of all SDK functions
- Thread safety improvements
- Enhanced documentation

Usage:
------
    import zkfinger_enhanced as zkf

    # Initialize the SDK
    sdk = zkf.ZKFingerSDK()

    # Get device count
    device_count = sdk.get_device_count()

    # Open the first device
    device = sdk.open_device(0)

    # Acquire a fingerprint
    image, template = device.acquire_fingerprint()

    # Close the device when done
    device.close()

    # Clean up SDK resources
    sdk.terminate()

Author: Araray
Date: 2025-03-02
"""

import ctypes
import platform
import threading
import time
import logging
from typing import Tuple, Optional, List, Any, Dict


# Set up logging
logger = logging.getLogger(__name__)


# Error codes from libzkfperrdef.h
ZKFP_ERR_OK = 0             # Operation succeeded
ZKFP_ERR_INITLIB = -1       # Failed to initialize the algorithm library
ZKFP_ERR_NODEVICE = -3      # No device connected
ZKFP_ERR_INVALIDPARAM = -5  # Invalid parameter
ZKFP_ERR_INVALIDHANDLE = -7 # Invalid handle
ZKFP_ERR_CAPTURE = -8       # Failed to capture image
ZKFP_ERR_EXTRACT = -9       # Failed to extract fingerprint template
ZKFP_ERR_ABSORT = -10       # Suspension operation
ZKFP_ERR_BUSY = -12         # Device is busy
ZKFP_ERR_DELETE = -14       # Failed to delete fingerprint template
ZKFP_ERR_OTHER = -17        # Other operation failure
ZKFP_ERR_CANCELED = -18     # Capture canceled
ZKFP_ERR_VERIFY = -20       # Fingerprint comparison failed
ZKFP_ERR_IMGPROCESS = -24   # Image processing failed


# Constants from libzkfptype.h
MAX_TEMPLATE_SIZE = 2048    # Maximum length of a template
FP_THRESHOLD_CODE = 1       # Fingerprint 1:1 threshold parameter code
FP_MTHRESHOLD_CODE = 2      # Fingerprint 1:N threshold parameter code


# Parameter codes from API.md appendix
PARAM_CODE_WIDTH = 1        # Image width (read-only)
PARAM_CODE_HEIGHT = 2       # Image height (read-only)
PARAM_CODE_DPI = 3          # Image DPI (read-write)
PARAM_CODE_IMAGE_SIZE = 106 # Image data size (read-only)
PARAM_CODE_WHITE_LIGHT = 101 # White light (write-only, 1: blinks, 0: disabled)
PARAM_CODE_GREEN_LIGHT = 102 # Green light (write-only, 1: blinks, 0: disabled)
PARAM_CODE_RED_LIGHT = 103   # Red light (write-only, 1: blinks, 0: disabled)
PARAM_CODE_BUZZER = 104     # Buzzer (write-only, 1: starts, 0: disabled)
PARAM_CODE_FORMAT = 10001   # Template format (write-only, 0: ANSI378, 1: ISO 19794-2)


class ZKFingerError(Exception):
    """Custom exception for errors raised by the ZKFinger SDK wrapper."""

    def __init__(self, message: str, error_code: int = None):
        """
        Initialize a ZKFingerError.

        Args:
            message: Error message
            error_code: SDK error code if available
        """
        self.error_code = error_code

        if error_code is not None:
            error_description = self._get_error_description(error_code)
            super().__init__(f"{message} (Error code: {error_code}, {error_description})")
        else:
            super().__init__(message)

    @staticmethod
    def _get_error_description(error_code: int) -> str:
        """Get a human-readable description of an error code."""
        error_map = {
            ZKFP_ERR_OK: "Operation succeeded",
            ZKFP_ERR_INITLIB: "Failed to initialize the algorithm library",
            ZKFP_ERR_NODEVICE: "No device connected",
            ZKFP_ERR_INVALIDPARAM: "Invalid parameter",
            ZKFP_ERR_INVALIDHANDLE: "Invalid handle",
            ZKFP_ERR_CAPTURE: "Failed to capture image",
            ZKFP_ERR_EXTRACT: "Failed to extract fingerprint template",
            ZKFP_ERR_ABSORT: "Suspension operation",
            ZKFP_ERR_BUSY: "Device is busy",
            ZKFP_ERR_DELETE: "Failed to delete fingerprint template",
            ZKFP_ERR_OTHER: "Other operation failure",
            ZKFP_ERR_CANCELED: "Capture canceled",
            ZKFP_ERR_VERIFY: "Fingerprint comparison failed",
            ZKFP_ERR_IMGPROCESS: "Image processing failed"
        }
        return error_map.get(error_code, "Unknown error")


class ZKFingerSDK:
    """
    Python wrapper for the ZKFinger SDK.

    This class initializes the SDK library and provides methods to enumerate
    and open fingerprint devices. It also handles proper cleanup of resources.
    """

    def __init__(self, lib_path: str = None):
        """
        Initialize the ZKFinger SDK.

        Args:
            lib_path: Optional path to the shared library file.
                     If None, a default name is chosen based on the OS.

        Raises:
            ZKFingerError: If the shared library cannot be loaded or if initialization fails.
        """
        self._lock = threading.RLock()  # For thread safety
        self._initialized = False
        self._open_devices = []
        self._open_db_caches = []

        # Determine default library name based on the operating system
        if lib_path is None:
            if platform.system() == 'Windows':
                lib_name = "zkfinger.dll"
            else:
                lib_name = "libzkfp.so"
            lib_path = lib_name

        # Attempt to load the shared library
        try:
            self.lib = ctypes.CDLL(lib_path)
            logger.info(f"Successfully loaded library: {lib_path}")
        except OSError as e:
            error_msg = f"Could not load library '{lib_path}': {e}"
            logger.error(error_msg)
            raise ZKFingerError(error_msg)

        # Set up the function prototypes
        self._setup_functions()

        # Initialize the SDK
        with self._lock:
            ret = self.lib.ZKFPM_Init()
            if ret != ZKFP_ERR_OK:
                error_msg = f"ZKFPM_Init failed"
                logger.error(f"{error_msg} with error code: {ret}")
                raise ZKFingerError(error_msg, ret)

            self._initialized = True
            logger.info("ZKFinger SDK initialized successfully")

    def _setup_functions(self):
        """Set up the function prototypes for the SDK functions."""
        # Basic SDK functions
        self._setup_basic_functions()

        # Device parameter functions
        self._setup_parameter_functions()

        # Database functions
        self._setup_database_functions()

    def _setup_basic_functions(self):
        """Set up basic SDK function prototypes."""
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

        # int ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage,
        #                             unsigned char* fpTemplate, unsigned int* cbTemplate);
        self.lib.ZKFPM_AcquireFingerprint.restype = ctypes.c_int
        self.lib.ZKFPM_AcquireFingerprint.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint)
        ]

    def _setup_parameter_functions(self):
        """Set up parameter-related function prototypes."""
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

    def _setup_database_functions(self):
        """Set up database-related function prototypes."""
        # HANDLE ZKFPM_DBInit(void);
        self.lib.ZKFPM_DBInit.restype = ctypes.c_void_p
        self.lib.ZKFPM_DBInit.argtypes = []

        # int ZKFPM_DBFree(HANDLE hDBCache);
        self.lib.ZKFPM_DBFree.restype = ctypes.c_int
        self.lib.ZKFPM_DBFree.argtypes = [ctypes.c_void_p]

        # int ZKFPM_DBMerge(HANDLE hDBCache, unsigned char* temp1, unsigned char* temp2,
        #                   unsigned char* temp3, unsigned char* regTemp, unsigned int* cbRegTemp);
        self.lib.ZKFPM_DBMerge.restype = ctypes.c_int
        self.lib.ZKFPM_DBMerge.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint)
        ]

        # int ZKFPM_DBAdd(HANDLE hDBCache, unsigned int tid, unsigned char* pTemplate, unsigned int cbTemplate);
        self.lib.ZKFPM_DBAdd.restype = ctypes.c_int
        self.lib.ZKFPM_DBAdd.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint
        ]

        # int ZKFPM_DBDel(HANDLE hDBCache, unsigned int tid);
        self.lib.ZKFPM_DBDel.restype = ctypes.c_int
        self.lib.ZKFPM_DBDel.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint
        ]

        # int ZKFPM_DBClear(HANDLE hDBCache);
        self.lib.ZKFPM_DBClear.restype = ctypes.c_int
        self.lib.ZKFPM_DBClear.argtypes = [ctypes.c_void_p]

        # int ZKFPM_DBCount(HANDLE hDBCache, unsigned int* count);
        self.lib.ZKFPM_DBCount.restype = ctypes.c_int
        self.lib.ZKFPM_DBCount.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint)
        ]

        # int ZKFPM_DBIdentify(HANDLE hDBCache, unsigned char* pTemplate, unsigned int cbTemplate,
        #                      unsigned int* tid, unsigned int* score);
        self.lib.ZKFPM_DBIdentify.restype = ctypes.c_int
        self.lib.ZKFPM_DBIdentify.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint)
        ]

        # int ZKFPM_DBMatch(HANDLE hDBCache, unsigned char* pTemplate1, unsigned int cbTemplate1,
        #                   unsigned char* pTemplate2, unsigned int cbTemplate2);
        self.lib.ZKFPM_DBMatch.restype = ctypes.c_int
        self.lib.ZKFPM_DBMatch.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint
        ]

    def __del__(self):
        """Destructor: Terminates the SDK when the object is garbage-collected."""
        self.terminate()

    def terminate(self):
        """
        Terminate the SDK and free resources.

        This method closes all open devices and DB caches and terminates the SDK.
        It's safe to call this method multiple times.

        Raises:
            ZKFingerError: If terminating the SDK fails.
        """
        with self._lock:
            if self._initialized:
                # Close any open devices
                for device in list(self._open_devices):
                    try:
                        device.close()
                    except Exception as e:
                        logger.warning(f"Error closing device during cleanup: {e}")

                # Free any open DB caches
                for db_cache in list(self._open_db_caches):
                    try:
                        self.free_db_cache(db_cache)
                    except Exception as e:
                        logger.warning(f"Error freeing DB cache during cleanup: {e}")

                # Terminate the SDK
                ret = self.lib.ZKFPM_Terminate()
                if ret != ZKFP_ERR_OK:
                    logger.error(f"ZKFPM_Terminate failed with error code: {ret}")
                    # Don't raise here to ensure cleanup continues

                self._initialized = False
                logger.info("ZKFinger SDK terminated")

    def get_device_count(self) -> int:
        """
        Get the number of connected fingerprint devices.

        Returns:
            The number of connected devices.

        Raises:
            ZKFingerError: If getting the device count fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            count = self.lib.ZKFPM_GetDeviceCount()
            if count < 0:
                error_msg = "Failed to get device count"
                logger.error(f"{error_msg}: {count}")
                raise ZKFingerError(error_msg, count)

            logger.info(f"Found {count} device(s)")
            return count

    def open_device(self, index: int) -> 'FingerprintDevice':
        """
        Open a fingerprint device.

        Args:
            index: Device index (0-based).

        Returns:
            A FingerprintDevice instance representing the opened device.

        Raises:
            ZKFingerError: If opening the device fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            handle = self.lib.ZKFPM_OpenDevice(index)
            if not handle:
                error_msg = f"Failed to open device at index {index}"
                logger.error(error_msg)
                raise ZKFingerError(error_msg, ZKFP_ERR_NODEVICE)

            device = FingerprintDevice(self, handle, index)
            self._open_devices.append(device)
            logger.info(f"Opened device at index {index}")
            return device

    def init_db_cache(self) -> ctypes.c_void_p:
        """
        Initialize a database cache for fingerprint operations.

        Returns:
            A handle to the initialized DB cache.

        Raises:
            ZKFingerError: If initializing the DB cache fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            db_cache = self.lib.ZKFPM_DBInit()
            if not db_cache:
                error_msg = "Failed to initialize DB cache"
                logger.error(error_msg)
                raise ZKFingerError(error_msg)

            self._open_db_caches.append(db_cache)
            logger.debug("Initialized new DB cache")
            return db_cache

    def free_db_cache(self, db_cache: ctypes.c_void_p):
        """
        Free a database cache.

        Args:
            db_cache: DB cache handle to free.

        Raises:
            ZKFingerError: If freeing the DB cache fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            if db_cache in self._open_db_caches:
                ret = self.lib.ZKFPM_DBFree(db_cache)
                if ret != ZKFP_ERR_OK:
                    error_msg = "Failed to free DB cache"
                    logger.error(f"{error_msg}: {ret}")
                    raise ZKFingerError(error_msg, ret)

                self._open_db_caches.remove(db_cache)
                logger.debug("Freed DB cache")

    def db_match(self, db_cache: ctypes.c_void_p, template1: bytes, template2: bytes) -> int:
        """
        Match two fingerprint templates.

        Args:
            db_cache: DB cache handle.
            template1: First fingerprint template.
            template2: Second fingerprint template.

        Returns:
            Match score (0-100). Higher values indicate better matches.

        Raises:
            ZKFingerError: If matching the templates fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            # Convert templates to C types
            c_template1 = (ctypes.c_ubyte * len(template1))(*template1)
            c_template2 = (ctypes.c_ubyte * len(template2))(*template2)

            score = self.lib.ZKFPM_DBMatch(
                db_cache,
                ctypes.cast(c_template1, ctypes.POINTER(ctypes.c_ubyte)),
                len(template1),
                ctypes.cast(c_template2, ctypes.POINTER(ctypes.c_ubyte)),
                len(template2)
            )

            if score < 0:
                error_msg = "Template matching failed"
                logger.error(f"{error_msg}: {score}")
                raise ZKFingerError(error_msg, score)

            logger.debug(f"Match score: {score}")
            return score

    def db_identify(self, db_cache: ctypes.c_void_p, template: bytes) -> Tuple[int, int]:
        """
        Identify a fingerprint template against the templates in the DB cache.

        Args:
            db_cache: DB cache handle.
            template: Fingerprint template to identify.

        Returns:
            Tuple of (template_id, match_score).

        Raises:
            ZKFingerError: If the identification fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            # Convert template to C type
            c_template = (ctypes.c_ubyte * len(template))(*template)
            c_tid = ctypes.c_uint(0)
            c_score = ctypes.c_uint(0)

            ret = self.lib.ZKFPM_DBIdentify(
                db_cache,
                ctypes.cast(c_template, ctypes.POINTER(ctypes.c_ubyte)),
                len(template),
                ctypes.byref(c_tid),
                ctypes.byref(c_score)
            )

            if ret != ZKFP_ERR_OK:
                error_msg = "Template identification failed"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            tid = c_tid.value
            score = c_score.value
            logger.debug(f"Identified template with ID {tid} (score: {score})")
            return tid, score

    def db_add(self, db_cache: ctypes.c_void_p, tid: int, template: bytes) -> bool:
        """
        Add a fingerprint template to the DB cache.

        Args:
            db_cache: DB cache handle.
            tid: Template ID.
            template: Fingerprint template to add.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If adding the template fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            # Convert template to C type
            c_template = (ctypes.c_ubyte * len(template))(*template)

            ret = self.lib.ZKFPM_DBAdd(
                db_cache,
                tid,
                ctypes.cast(c_template, ctypes.POINTER(ctypes.c_ubyte)),
                len(template)
            )

            if ret != ZKFP_ERR_OK:
                error_msg = f"Failed to add template with ID {tid}"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            logger.debug(f"Added template with ID {tid}")
            return True

    def db_delete(self, db_cache: ctypes.c_void_p, tid: int) -> bool:
        """
        Delete a template from the DB cache.

        Args:
            db_cache: DB cache handle.
            tid: Template ID to delete.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If deleting the template fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            ret = self.lib.ZKFPM_DBDel(db_cache, tid)

            if ret != ZKFP_ERR_OK:
                error_msg = f"Failed to delete template with ID {tid}"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            logger.debug(f"Deleted template with ID {tid}")
            return True

    def db_clear(self, db_cache: ctypes.c_void_p) -> bool:
        """
        Clear all templates from the DB cache.

        Args:
            db_cache: DB cache handle.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If clearing the DB cache fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            ret = self.lib.ZKFPM_DBClear(db_cache)

            if ret != ZKFP_ERR_OK:
                error_msg = "Failed to clear DB cache"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            logger.debug("Cleared DB cache")
            return True

    def db_count(self, db_cache: ctypes.c_void_p) -> int:
        """
        Get the number of templates in the DB cache.

        Args:
            db_cache: DB cache handle.

        Returns:
            Number of templates.

        Raises:
            ZKFingerError: If getting the template count fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            c_count = ctypes.c_uint(0)

            ret = self.lib.ZKFPM_DBCount(db_cache, ctypes.byref(c_count))

            if ret != ZKFP_ERR_OK:
                error_msg = "Failed to get template count"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            count = c_count.value
            logger.debug(f"DB cache contains {count} templates")
            return count

    def db_merge(self, db_cache: ctypes.c_void_p, template1: bytes, template2: bytes,
                template3: bytes = None) -> bytes:
        """
        Merge multiple fingerprint templates into a single template.

        Args:
            db_cache: DB cache handle.
            template1: First fingerprint template.
            template2: Second fingerprint template.
            template3: Third fingerprint template (optional).

        Returns:
            The merged fingerprint template.

        Raises:
            ZKFingerError: If merging the templates fails.
        """
        with self._lock:
            if not self._initialized:
                raise ZKFingerError("SDK not initialized")

            # If template3 is not provided, use template2 again
            if template3 is None:
                template3 = template2

            # Convert templates to C types
            c_template1 = (ctypes.c_ubyte * len(template1))(*template1)
            c_template2 = (ctypes.c_ubyte * len(template2))(*template2)
            c_template3 = (ctypes.c_ubyte * len(template3))(*template3)

            # Prepare merged template buffer
            c_merged_template = (ctypes.c_ubyte * MAX_TEMPLATE_SIZE)()
            c_merged_size = ctypes.c_uint(MAX_TEMPLATE_SIZE)

            ret = self.lib.ZKFPM_DBMerge(
                db_cache,
                ctypes.cast(c_template1, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.cast(c_template2, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.cast(c_template3, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.cast(c_merged_template, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(c_merged_size)
            )

            if ret != ZKFP_ERR_OK:
                error_msg = "Template merge failed"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            # Convert to bytes
            merged_template = bytes(c_merged_template[:c_merged_size.value])
            logger.debug(f"Merged {len(template1)}, {len(template2)}, {len(template3)} byte templates into {len(merged_template)} byte template")
            return merged_template


class FingerprintDevice:
    """
    Class representing a fingerprint device.

    This class provides methods to interact with a specific fingerprint device,
    such as acquiring fingerprints and setting device parameters.
    """

    def __init__(self, sdk: ZKFingerSDK, handle: ctypes.c_void_p, index: int):
        """
        Initialize a FingerprintDevice instance.

        Args:
            sdk: The ZKFingerSDK instance.
            handle: Device handle returned by ZKFPM_OpenDevice.
            index: Device index.
        """
        self.sdk = sdk
        self.handle = handle
        self.index = index
        self._lock = threading.RLock()  # For thread safety
        self._closed = False

        # Cache device parameters
        try:
            self.width = self.get_parameter(PARAM_CODE_WIDTH)
            self.height = self.get_parameter(PARAM_CODE_HEIGHT)
            self.image_size = self.width * self.height
            logger.info(f"Device parameters: width={self.width}, height={self.height}, image_size={self.image_size}")
        except ZKFingerError as e:
            logger.warning(f"Could not get device parameters: {e}")
            self.width = 0
            self.height = 0
            self.image_size = 0

    def __del__(self):
        """Destructor: Closes the device when the object is garbage-collected."""
        self.close()

    def close(self):
        """
        Close the fingerprint device.

        This method releases the device handle. It's safe to call this method multiple times.

        Raises:
            ZKFingerError: If closing the device fails.
        """
        with self._lock:
            if not self._closed and self.handle:
                ret = self.sdk.lib.ZKFPM_CloseDevice(self.handle)
                if ret != ZKFP_ERR_OK:
                    error_msg = f"Failed to close device at index {self.index}"
                    logger.error(f"{error_msg}: {ret}")
                    raise ZKFingerError(error_msg, ret)

                self._closed = True
                if self in self.sdk._open_devices:
                    self.sdk._open_devices.remove(self)
                logger.info(f"Closed device at index {self.index}")
                self.handle = None

    def acquire_fingerprint(self, fp_image_size: int = None, fp_template_size: int = MAX_TEMPLATE_SIZE,
                           max_retries: int = 10, retry_delay: float = 0.5) -> Tuple[bytes, bytes]:
        """
        Acquire a fingerprint from the device.

        This method captures both a fingerprint image and a template.

        Args:
            fp_image_size: Size of the fingerprint image buffer in bytes.
                          If None, use the device's reported image size.
            fp_template_size: Size of the fingerprint template buffer in bytes.
            max_retries: Maximum number of acquisition retries.
            retry_delay: Delay between retries in seconds.

        Returns:
            Tuple of (image_data, template_data).

        Raises:
            ZKFingerError: If fingerprint acquisition fails after all retries.
        """
        with self._lock:
            if self._closed:
                raise ZKFingerError("Device is closed")

            # Use cached image size if not provided
            if fp_image_size is None:
                if self.image_size <= 0:
                    raise ZKFingerError("Unknown image size, please specify fp_image_size")
                fp_image_size = self.image_size

            for attempt in range(max_retries):
                # Allocate buffers for the image and template
                fp_image = (ctypes.c_ubyte * fp_image_size)()
                fp_template = (ctypes.c_ubyte * fp_template_size)()
                template_size = ctypes.c_uint(fp_template_size)

                # Acquire fingerprint
                ret = self.sdk.lib.ZKFPM_AcquireFingerprint(
                    self.handle,
                    ctypes.cast(fp_image, ctypes.POINTER(ctypes.c_ubyte)),
                    fp_image_size,
                    ctypes.cast(fp_template, ctypes.POINTER(ctypes.c_ubyte)),
                    ctypes.byref(template_size)
                )

                if ret == ZKFP_ERR_OK:
                    # Success
                    image_data = bytes(fp_image)
                    template_data = bytes(fp_template[:template_size.value])
                    logger.info(f"Fingerprint acquired successfully on attempt {attempt + 1}, template size: {template_size.value} bytes")
                    return image_data, template_data

                elif ret == ZKFP_ERR_CAPTURE:
                    # Failed to capture image, retry
                    logger.debug(f"Attempt {attempt + 1}/{max_retries}: Failed to capture image, retrying in {retry_delay}s...")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                    else:
                        error_msg = "Failed to capture fingerprint after maximum retries"
                        logger.error(error_msg)
                        raise ZKFingerError(error_msg, ret)

                else:
                    # Other error, don't retry
                    error_msg = "Fingerprint acquisition failed"
                    logger.error(f"{error_msg}: {ret}")
                    raise ZKFingerError(error_msg, ret)

            # This should not be reached due to the raise in the loop
            raise ZKFingerError("Failed to acquire fingerprint")

    def set_parameter(self, param_code: int, value: int) -> bool:
        """
        Set a device parameter.

        Args:
            param_code: Parameter code.
            value: Parameter value.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If setting the parameter fails.
        """
        with self._lock:
            if self._closed:
                raise ZKFingerError("Device is closed")

            # Convert value to bytes
            c_value = ctypes.c_int(value)
            param_bytes = (ctypes.c_ubyte * ctypes.sizeof(c_value))()
            ctypes.memmove(param_bytes, ctypes.byref(c_value), ctypes.sizeof(c_value))

            ret = self.sdk.lib.ZKFPM_SetParameters(
                self.handle,
                param_code,
                param_bytes,
                ctypes.sizeof(c_value)
            )

            if ret != ZKFP_ERR_OK:
                error_msg = f"Failed to set parameter {param_code} to {value}"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            logger.debug(f"Set parameter {param_code} to {value}")
            return True

    def get_parameter(self, param_code: int) -> int:
        """
        Get a device parameter.

        Args:
            param_code: Parameter code.

        Returns:
            Parameter value.

        Raises:
            ZKFingerError: If getting the parameter fails.
        """
        with self._lock:
            if self._closed:
                raise ZKFingerError("Device is closed")

            # Prepare buffer for parameter value
            param_bytes = (ctypes.c_ubyte * 4)()
            param_size = ctypes.c_uint(4)

            ret = self.sdk.lib.ZKFPM_GetParameters(
                self.handle,
                param_code,
                param_bytes,
                ctypes.byref(param_size)
            )

            if ret != ZKFP_ERR_OK:
                error_msg = f"Failed to get parameter {param_code}"
                logger.error(f"{error_msg}: {ret}")
                raise ZKFingerError(error_msg, ret)

            # Convert bytes to int
            value = ctypes.cast(param_bytes, ctypes.POINTER(ctypes.c_int)).contents.value
            logger.debug(f"Got parameter {param_code} = {value}")
            return value

    def set_led(self, white: bool = False, green: bool = False, red: bool = False) -> bool:
        """
        Control the device LEDs.

        Args:
            white: Whether to enable the white LED.
            green: Whether to enable the green LED.
            red: Whether to enable the red LED.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If setting the LEDs fails.
        """
        try:
            if white:
                self.set_parameter(PARAM_CODE_WHITE_LIGHT, 1)
            else:
                self.set_parameter(PARAM_CODE_WHITE_LIGHT, 0)

            if green:
                self.set_parameter(PARAM_CODE_GREEN_LIGHT, 1)
            else:
                self.set_parameter(PARAM_CODE_GREEN_LIGHT, 0)

            if red:
                self.set_parameter(PARAM_CODE_RED_LIGHT, 1)
            else:
                self.set_parameter(PARAM_CODE_RED_LIGHT, 0)

            return True
        except ZKFingerError as e:
            logger.error(f"Failed to set LEDs: {e}")
            raise

    def set_buzzer(self, enabled: bool) -> bool:
        """
        Control the device buzzer.

        Args:
            enabled: Whether to enable the buzzer.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If setting the buzzer fails.
        """
        try:
            if enabled:
                self.set_parameter(PARAM_CODE_BUZZER, 1)
            else:
                self.set_parameter(PARAM_CODE_BUZZER, 0)

            return True
        except ZKFingerError as e:
            logger.error(f"Failed to set buzzer: {e}")
            raise

    def set_template_format(self, iso_format: bool) -> bool:
        """
        Set the template format.

        Args:
            iso_format: True for ISO 19794-2 format, False for ANSI378 format.

        Returns:
            True if successful.

        Raises:
            ZKFingerError: If setting the template format fails.
        """
        try:
            if iso_format:
                self.set_parameter(PARAM_CODE_FORMAT, 1)
            else:
                self.set_parameter(PARAM_CODE_FORMAT, 0)

            return True
        except ZKFingerError as e:
            logger.error(f"Failed to set template format: {e}")
            raise

    def __enter__(self) -> 'FingerprintDevice':
        """Context manager entry: returns self."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit: closes the device."""
        self.close()
