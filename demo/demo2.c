#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include "include/zkinterface.h"
#include "include/libzkfperrdef.h"
#include "include/libzkfptype.h"
#include "include/libzkfp.h"

#ifndef HANDLE
#define HANDLE void *
#endif

#define ENROLLCNT 3
HANDLE m_libHandle = NULL;
HANDLE m_hDevice = NULL;
HANDLE m_hDBCache = NULL;
unsigned char *m_pImgBuf = NULL;
unsigned char m_arrPreRegTemps[ENROLLCNT][MAX_TEMPLATE_SIZE];
unsigned int m_arrPreTempsLen[3];
int m_nLastRegTempLen = 0;
unsigned char m_szLastRegTemplate[MAX_TEMPLATE_SIZE];
int m_bIdentify = 0;
int m_bRegister = 0;
int m_tid = 0;
int m_enrollIdx = 0;

static void sighandler(int signo)
{
	if(m_pImgBuf)
	{
		free(m_pImgBuf);
		m_pImgBuf = NULL;
	}
	if(m_hDevice)
	{
		ZKFPM_CloseDevice(m_hDevice);
		ZKFPM_Terminate();
	}
	printf("sighandler\n");
	exit(signo);
}

void SetExitSignalHandle(void)
{
	int index;
	struct sigaction sa;
	int sigs[] = {
		SIGILL, SIGFPE, SIGABRT, SIGBUS,
		SIGSEGV, SIGHUP, SIGINT, SIGQUIT,
		SIGTERM
	};

	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;
	for(index = 0; index < sizeof(sigs)/sizeof(sigs[0]); ++index) {
		if (sigaction(sigs[index], &sa, NULL) == -1) {
			perror("Could not set signal handler");
		}
	}
}

static void *LoadSym(void *pHandle, const char *pSymbol)
{
        void *pAPI = NULL;
        char *pErrMsg = NULL;

        pAPI = dlsym(pHandle, pSymbol);
        pErrMsg = dlerror();
        if (NULL != pErrMsg)
        {
                printf("Load function error: %s\n", pErrMsg);
                return NULL;
        }

        return pAPI;
}


int Loadlib()
{
	m_libHandle = dlopen("libzkfp.so", RTLD_NOW);

	if (NULL == m_libHandle)
	{
		printf("Load libzkfp failed,error:%s\n", dlerror());
		
		return 0;
	}

	ZKFPM_Init = LoadSym(m_libHandle, "ZKFPM_Init");
	if (NULL == ZKFPM_Init)
	{
		printf("load ZKFPM_Init failed\n");

		return 0;
	}
	else
	{
		printf("load ZKFPM_Init success\n");
	}

	ZKFPM_Terminate = LoadSym(m_libHandle, "ZKFPM_Terminate");
	ZKFPM_GetDeviceCount = LoadSym(m_libHandle, "ZKFPM_GetDeviceCount");
	ZKFPM_OpenDevice = LoadSym(m_libHandle, "ZKFPM_OpenDevice");
	ZKFPM_CloseDevice = LoadSym(m_libHandle, "ZKFPM_CloseDevice");
	ZKFPM_SetParameters = LoadSym(m_libHandle, "ZKFPM_SetParameters");
	ZKFPM_GetParameters = LoadSym(m_libHandle, "ZKFPM_GetParameters");
	ZKFPM_AcquireFingerprint = LoadSym(m_libHandle, "ZKFPM_AcquireFingerprint");
	ZKFPM_DBInit = LoadSym(m_libHandle, "ZKFPM_DBInit");
	ZKFPM_DBFree = LoadSym(m_libHandle, "ZKFPM_DBFree");
	ZKFPM_DBMerge = LoadSym(m_libHandle, "ZKFPM_DBMerge");
	ZKFPM_DBDel = LoadSym(m_libHandle, "ZKFPM_DBDel");
	ZKFPM_DBAdd = LoadSym(m_libHandle, "ZKFPM_DBAdd");
	ZKFPM_DBClear = LoadSym(m_libHandle, "ZKFPM_DBClear");
	ZKFPM_DBCount = LoadSym(m_libHandle, "ZKFPM_DBCount");
	ZKFPM_DBIdentify = LoadSym(m_libHandle, "ZKFPM_DBIdentify");
	ZKFPM_DBMatch = LoadSym(m_libHandle, "ZKFPM_DBMatch");

	return 1;
}

unsigned int GetTickCount()
{
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
	return (tv.tv_sec*1000 + tv.tv_usec/1000);
}

void DoVerify(HANDLE handle, unsigned char *temp, int len)
{
	if(m_nLastRegTempLen > 0)	//enrolled template
	{
		if(m_bIdentify)
		{
			int ret = ZKFP_ERR_OK;
			unsigned int tid = 0;
			unsigned int score = 0;
			ret = ZKFPM_DBIdentify(handle, temp, len, &tid, &score);
			if (ZKFP_ERR_OK != ret)
			{
				printf("Identify failed, ret = %d\n", ret);
			}
			else
			{
				printf("Identify succ, tid=%d, score=%d\n", tid, score);
			}
		}
		else
		{
			int ret = ZKFPM_DBMatch(handle, m_szLastRegTemplate, m_nLastRegTempLen, temp, len);
			if (ZKFP_ERR_OK >= ret)
			{
				printf("Verify failed, ret=%d\n", ret);
			}
			else
			{
				printf("Verify succ, score=%d\n", ret);
			}
		}
	}
	else
	{
		printf("Please register first\n");
	}
}

int DoRegister(HANDLE handle, unsigned char* temp, int len)
{
	int ret = 0;
	if(m_enrollIdx >= ENROLLCNT)
	{
		m_enrollIdx = 0;	//restart enroll
		return 1;
	}
	if(m_enrollIdx > 0)
	{
		ret = ZKFPM_DBMatch(m_hDBCache, m_arrPreRegTemps[m_enrollIdx-1], m_arrPreTempsLen[m_enrollIdx-1], temp, len);
		printf("ZKFPM_DBMatch ret=%d\n", ret);
		if(ZKFP_ERR_OK >= ret)
		{
			m_enrollIdx = 0;
			printf("Resigter failed, please place the same finger\n");
			return 1;
		}
	}
	m_arrPreTempsLen[m_enrollIdx] = len;
	memcpy(m_arrPreRegTemps[m_enrollIdx], temp, len);
	if(++m_enrollIdx >= ENROLLCNT)
	{
		int ret = 0;
		unsigned char szRegTemp[MAX_TEMPLATE_SIZE] = {0x0};
		unsigned int cbRegTemp = MAX_TEMPLATE_SIZE;
		ret = ZKFPM_DBMerge(m_hDBCache, m_arrPreRegTemps[0], m_arrPreRegTemps[1], m_arrPreRegTemps[2], szRegTemp, &cbRegTemp);
		m_enrollIdx = 0;
		if(ZKFP_ERR_OK == ret)
		{
			ret = ZKFPM_DBAdd(m_hDBCache, m_tid++, szRegTemp, cbRegTemp);
			if(ZKFP_ERR_OK == ret)
			{
				memcpy(m_szLastRegTemplate, szRegTemp, cbRegTemp);
				m_nLastRegTempLen = cbRegTemp;
				ZKFPM_DBCount(m_hDBCache, &ret);
				printf("Register tid=%d succ, DBCount=%d\n", m_tid-1, ret);
			}
			else
			{
				printf("ZKFPM_DBAdd failed, ret=%d\n", ret);
			}
		}
		else
		{
			printf("Register failed, ZKFPM_DBMerge=%d\n", ret);
		}
		return 1;
	}
	else
	{
		printf("Please still place %d times\n", ENROLLCNT-m_enrollIdx);
		return 0;
	}
}

int main(int argc, char *argv[])
{
	int m_imgFPWidth = 0;
	int m_imgFPHeight = 0;
	int m_bRegister = 0;
	int ret = 0;
	char cFun;
	
	if(!Loadlib())
	{
		return 0;
	}
	
	SetExitSignalHandle();
	
	if((ret = ZKFPM_Init()) != ZKFP_ERR_OK)
	{
		printf("Init ZKFPM failed, ret=%d\n", ret);
		return 0;
	}
	printf("device count=%d\n", ZKFPM_GetDeviceCount());
	if((m_hDevice = ZKFPM_OpenDevice(0) ) == NULL)
	{
		printf("Open device failed\n");
		ZKFPM_Terminate();
		return 0;
	}
	m_hDBCache = ZKFPM_DBInit();
	if (NULL == m_hDBCache)
	{
		printf("Create DBCache failed\n");
		ZKFPM_CloseDevice(m_hDevice);
		ZKFPM_Terminate();
		return 0;
	}
	char paramValue[4] = {0x0};
	int cbParamValue = 4;
	ZKFPM_GetParameters(m_hDevice, 1, paramValue, &cbParamValue);
	memcpy(&m_imgFPWidth, paramValue, sizeof(int));

	memset(paramValue, 0, 4);
	cbParamValue = 4;
	ZKFPM_GetParameters(m_hDevice, 2, paramValue, &cbParamValue);
	memcpy(&m_imgFPHeight, paramValue, sizeof(int));
		



	m_pImgBuf = (unsigned char *)malloc(m_imgFPWidth*m_imgFPHeight);
	m_nLastRegTempLen = 0;
	memset(&m_szLastRegTemplate, 0x0, sizeof(m_szLastRegTemplate));

	printf("Init Succ\n");
	m_tid = 1;
	m_enrollIdx = 0;

	while(1)
	{
		printf("Please input key\ 
				\n['r' or 'R']: Register\
				\n['v' or 'V']: Verify]\
				\n['i' or 'I']: Identify\
				\n['e' or 'E']: Exit\n");
				
		scanf("%s", &cFun);
		
		if(('R' == cFun) || ('r' == cFun)) //Register
		{
			m_bRegister = 1;
			printf("Doing resiger, Please place finger 3 times\n");
		}
		else if(('V' == cFun) || ('v' == cFun)) //Verify
		{
			m_bRegister = 0;
			m_bIdentify = 0;
			printf("Doing verify, Please place finger\n");
		}
		else if(('I' == cFun) || ('i' == cFun)) //Identify
		{
			m_bRegister = 0;
			m_bIdentify = 1;
			printf("Doing identify, Please place finger\n");
		}
		else if(('E' == cFun) || ('e' == cFun))
		{
			break;
		}
		else
		{
			printf("Invalid key\n");
			continue;
		}
		
		
		while(1)
		{
			unsigned char szTemplate[MAX_TEMPLATE_SIZE];
			unsigned int tempLen = MAX_TEMPLATE_SIZE;
			int nTick = 0;
			
			nTick = GetTickCount();
			int ret = ZKFPM_AcquireFingerprint(m_hDevice, m_pImgBuf, m_imgFPWidth*m_imgFPHeight, szTemplate, &tempLen);			
			if (ZKFP_ERR_OK == ret)
			{
				printf("ZKFPM_AcquireFingerprint ret=%d, tempLen=%d, time=%d\n", ret, tempLen, GetTickCount()-nTick);
				if(m_bRegister) //Register
				{
					if(1 == DoRegister(m_hDBCache, szTemplate, tempLen))
					{
						break;
					}
				}
				else	//Identify
				{
					DoVerify(m_hDBCache, szTemplate, tempLen);
					break;
				}
			}
			
			usleep(100000);
		}
		
		
	}	
	
	if(m_pImgBuf)
	{
		free(m_pImgBuf);
		m_pImgBuf = NULL;
	}
	if(m_hDevice)
	{
		ZKFPM_CloseDevice(m_hDevice);
		ZKFPM_Terminate();
	}
	printf("Exit\n");
	return 1;
}
