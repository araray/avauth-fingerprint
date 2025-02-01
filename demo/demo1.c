/**
* File:   main.cpp
* Author: ruan
*
* Created on 16 August 2017, 9:28 AM
* sudo apt-get install libmysqlclient-dev
*/

//std
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdbool.h>

//zk
#include "include/zkinterface.h"
#include "include/libzkfperrdef.h"
#include "include/libzkfptype.h"
#include "include/libzkfp.h"

#define DEBUG
#ifdef DEBUG
#define LogOut (printf("===>%s(%d)-<%s>: ",__FILE__, __LINE__, __FUNCTION__), printf)
#else
#define LogOut
#endif

void * handle = NULL;
void * device = NULL;
void * fingerprint_cache = NULL;

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/*
 *	ZK Base 64 decode function
 */
int base64_decode( const char * base64, unsigned char * bindata ){
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
} 


static void *load_sym(void *p_handle, char const *p_symb){
	void *data_return = dlsym(p_handle, p_symb);
	
	char *err_msg = dlerror();
	if(err_msg != NULL){
	LogOut("Unable to load function from libary : %s", p_symb);
	return NULL;
	}
	
	return data_return;
}
 
 
 
void load_lib(){
	handle = dlopen("libzkfp.so", RTLD_NOW);
	if(!handle){
	LogOut("Unable to load library...\n");
	}
	 
	ZKFPM_Init = load_sym(handle, "ZKFPM_Init");
	ZKFPM_OpenDevice = load_sym(handle, "ZKFPM_OpenDevice");
	ZKFPM_DBInit = load_sym(handle, "ZKFPM_DBInit");
	ZKFPM_DBFree = load_sym(handle, "ZKFPM_DBFree");
	ZKFPM_DBAdd = load_sym(handle, "ZKFPM_DBAdd");
	ZKFPM_DBClear = load_sym(handle, "ZKFPM_DBClear");
	ZKFPM_DBCount = load_sym(handle, "ZKFPM_DBCount");
	ZKFPM_DBIdentify = load_sym(handle, "ZKFPM_DBIdentify");
	ZKFPM_DBDel = load_sym(handle, "ZKFPM_DBDel");
}
 
int init(){
	//load .so file and functions
	load_lib();
	LogOut("\n");
	
	//init device
	int init_return = ZKFPM_Init();
	if(init_return != ZKFP_ERR_OK){
		LogOut("Device init failed...\n");
		return 0;
	}
	
	//open device
	device = ZKFPM_OpenDevice(0);
	if(device == NULL){
		LogOut("Failed to open device...\n");
		return 0;
	}
	
	fingerprint_cache = ZKFPM_DBInit();
	if(fingerprint_cache == NULL){
		LogOut("Failed to init db cache...\n");
		return 0;
	}
	
	return 1;
}

int main(int argc, char** argv) {

   	char szTest[2048] = {0};  
    	if(!init()){
		LogOut("Main init failed...\n");
		return -1;
    	}
    	
    	while(true)
    	{
		int counter = 1;
		FILE *fp = fopen("templates.txt", "r");  
    		if(NULL == fp)  
     		{  
        		LogOut("failed to open dos.txt\n");  
        		return 1;  
    		}  

		while(true){

			int ret = 0;
			int ret2 = 0;
			int ret3 = 0;
			
			if(!feof(fp))  
   			{
       	 				memset(szTest, 0, 2048);  
        				fgets(szTest, sizeof(szTest) - 1, fp); // 包含了\n  
       			 		//LogOut("%s\n", szTest); 
			}else
			{
				LogOut("counter=%d\n",counter);
				break;	
			}
			unsigned char  tmp_template[3096] = {0x0};
			int tmp_template_len = base64_decode(szTest, tmp_template);

		
			//add template to buffer
			if(tmp_template_len){
				ret = ZKFPM_DBAdd(fingerprint_cache, counter, tmp_template, tmp_template_len);

				ZKFPM_DBCount(fingerprint_cache,&ret2);
				if(counter%10==0)
				{
					LogOut("============>ZKFPM_DBClear\n");
					ret3 = ZKFPM_DBClear(fingerprint_cache);
					LogOut("ret=%d,   ret2=%d,  ret3=%d,  counter=%d\n",ret,ret2,ret3,counter);
					break;
					
				}	
				
				counter++;
				LogOut("ret=%d,   ret2=%d,  ret3=%d,  counter=%d\n",ret,ret2,ret3,counter);
			}			
		}
	fclose(fp);	
		
	}			
	return 0;
}
 
 
