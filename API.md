# ZKFinger SDK Development Guide

## C API  
**Version:** 2.0  
**Date:** Sep 2016  

---

## Table of Contents

1. [Overview](#overview)  
2. [Privacy Policy](#privacy-policy)  
3. [System Requirements](#system-requirements)  
4. [Installation and Deployment](#installation-and-deployment)  
5. [Description of SDK Interfaces](#description-of-sdk-interfaces)  
   - [Type Definition](#type-definition)  
   - [Interface Description](#interface-description)  
6. [Appendices](#appendices)  

---

## 1. Overview

Please read this document carefully before using it to quickly understand how to use ZKFinger SDK.  

---

## 2. Privacy Policy

You are authorized to use the software.

---

## 3. System Requirements

- **Operating system:** Ubuntu  
- **Applicable development languages:** C, C++

---

## 4. Installation and Deployment

1. Copy all the library files from `lib-x86/lib-x64` to `/usr/lib`.

---

## 5. Description of SDK Interfaces

### 5.1 Type Definition

Refer to **libzkfptype.h**.  
The SDK interfaces use `__stdcall`.

```c
#ifdef _WIN32
#ifndef APICALL
#define APICALL __stdcall
#endif
~~~

#### 5.1.1 Constants

- **Maximum length of a template**

    ```c
    #define MAX_TEMPLATE_SIZE 2048
```

- **Fingerprint 1:1 threshold parameter code**

    ```c
    #define FP_THRESHOLD_CODE 1
    ```

- **Fingerprint 1:N threshold parameter code**

    ```c
    #define FP_MTHRESHOLD_CODE 2
    ```

------

### 5.2 Interface Description

#### 5.2.1 `ZKFPM_Init`

**Function:**

```c
int APICALL ZKFPM_Init();
```

**Purpose:** Initializes resources.

**Return Value:**

- `0` - Succeeded
- Others - Failed (See the Appendices)

------

#### 5.2.2 `ZKFPM_Terminate`

**Function:**

```c
int APICALL ZKFPM_Terminate();
```

**Purpose:** Releases resources.

**Return Value:**

- `0` - Succeeded
- Others - Failed (See the Appendices)

------

#### 5.2.3 `ZKFPM_GetDeviceCount`

**Function:**

```c
int APICALL ZKFPM_GetDeviceCount();
```

**Purpose:** Acquires the number of connected fingerprint devices.

**Return Value:**

- `>=0` - Device count
- `<0` - Function call failure (See the Appendices)

------

#### 5.2.4 `ZKFPM_OpenDevice`

**Function:**

```c
HANDLE APICALL ZKFPM_OpenDevice(int index);
```

**Purpose:** Starts a fingerprint device.

**Parameter:**

- `index` - Device index

**Return Value:**

- Device operation instance handle

------

#### 5.2.5 `ZKFPM_CloseDevice`

**Function:**

```c
int APICALL ZKFPM_CloseDevice(HANDLE hDevice);
```

**Purpose:** Shuts down a device.

**Parameter:**

- `hDevice` - Device operation instance handle

**Return Value:**

- `0` - Succeeded
- Others - Failed (See the Appendices)

------

#### 5.2.6 `ZKFPM_SetParameters`

**Function:**

```c
int APICALL ZKFPM_SetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int cbParamValue);
```

**Purpose:** Sets fingerprint reader parameters.

**Parameters:**

- `hDevice` - Device operation instance handle
- `nParamCode` - Parameter code
- `paramValue` - Parameter value
- `cbParamValue` - Parameter data length

**Return Value:**

- `0` - Succeeded
- Others - Failed (See the Appendices)

------

#### 5.2.7 `ZKFPM_GetParameters`

**Function:**

```c
int APICALL ZKFPM_GetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int* cbParamValue);
```

**Purpose:** Acquires fingerprint reader parameters.

**Return Value:**

- `0` - Succeeded
- Others - Failed (See the Appendices)

------

#### 5.2.8 `ZKFPM_AcquireFingerprint`

**Function:**

```c
int APICALL ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage, unsigned char* fpTemplate, unsigned int* cbTemplate);
```

**Purpose:** Captures a fingerprint template.

------

## 6. Appendices

### 6.1 Appendix 1: List of Common Parameter Codes

| Parameter Code | Property   | Data Type | Description                                   |
| -------------- | ---------- | --------- | --------------------------------------------- |
| 1              | Read-only  | Int       | Image width                                   |
| 2              | Read-only  | Int       | Image height                                  |
| 3              | Read-write | Int       | Image DPI (750/1000 recommended for children) |
| 106            | Read-only  | Int       | Image data size                               |
| 101            | Write-only | Int       | 1: White light blinks; 0: Disabled            |
| 102            | Write-only | Int       | 1: Green light blinks; 0: Disabled            |
| 103            | Write-only | Int       | 1: Red light blinks; 0: Disabled              |
| 104            | Write-only | Int       | 1: Buzzer starts; 0: Disabled                 |
| 10001          | Write-only | Int       | 0: ANSI378; 1: ISO 19794-2                    |

------

### 6.2 Appendix 2: Returned Error Values

| Code | Description                                |
| ---- | ------------------------------------------ |
| 0    | Operation succeeded                        |
| -1   | Failed to initialize the algorithm library |
| -3   | No device connected                        |
| -5   | Invalid parameter                          |
| -7   | Invalid handle                             |
| -8   | Failed to capture image                    |
| -9   | Failed to extract fingerprint template     |
| -10  | Suspension operation                       |
| -12  | Device is busy                             |
| -14  | Failed to delete fingerprint template      |
| -17  | Other operation failure                    |
| -18  | Capture canceled                           |
| -20  | Fingerprint comparison failed              |
| -24  | Image processing failed                    |

------

