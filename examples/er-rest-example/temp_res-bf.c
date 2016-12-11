/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Example resource
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "rest-engine.h"
#include "er-coap-block1.h"
#include "er-coap-separate.h"
#include "er-coap-transactions.h"
#include "tinydtls.h"
#include "dtls_config.h"
#include "hmac.h"
#include "jsonparse.h"
#include "base64.h"
#include "random.h"

#define MAX_DATA_LEN 256
#define BF_SIZE 1024
#define CHUNK_SIZE 10
#define CHAR_BIT 8

static uint8_t big_msg[MAX_DATA_LEN];
static size_t big_msg_len = 0;
LIST(block_list);
static uint8_t current_token[8];
static coap_separate_t request_metadata;
unsigned char userid[20];
unsigned char action[20];
unsigned short c2;
static uint8_t fin = 0;
static const char *keys[] ={"ReB5I4WTSMohvkwg","NM5oUPgQXbYxjgk9","JtCZyi2Q4p6xZ2ev","Mjhq6NHdxnZeSJnl","CzI8gKZk9dihdMaz","3HpAd4laqIEIb01m","xHudbRMj44OhOygP","FUXqYHQOZdeBbdvY","upAUFWBJYZzuXdJk","7rZe6z0fadoBEji7","XsbkOm3uJ0ooe7Yj","w5N05Ogd1SpFAVMf"};


static int bitArrayToInt32(bool arr[], int count)
{
    int ret = 0; int i;
    int tmp;
    for (i = 0; i < count; i++) {
        tmp = arr[i];
        ret |= tmp << (count - i - 1);
    }
    return ret;
}

static void xor_func(const char* s1, int s2, char* result)
{
	int temp;
	for (temp = 0; temp < strlen(s1); temp++){
  		result[temp] = s1[temp] ^ (s2+ temp) % 255; //printf("%d\n",result[temp]);
 	}//printf("\n");
	//return result;
}

static void hash_result(const char* key,const char* value, char* result) {
	unsigned int len = 20;
	unsigned char digest[DTLS_HMAC_MAX];
	dtls_hmac_context_t hmac_context;	
	dtls_hmac_init(&hmac_context, key, 16);
	dtls_hmac_update(&hmac_context, value, strlen(value));
	len = dtls_hmac_finalize(&hmac_context, digest);
	dtls_hmac_free(&hmac_context);
	int i;
	for(i = 0; i < 20; i++)
	sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);
}

static void bf_add(unsigned char* keys[], int numkey, const unsigned char* value, bool* bf) {
	int i,j;	
	for (j = 0;j < numkey;j++) {
		unsigned char result[DTLS_HMAC_MAX];
		size_t len;
		//const unsigned char temp[] = "abcde";
		dtls_hmac_context_t hmac_context;
		dtls_hmac_init(&hmac_context, keys[j], 16);
		dtls_hmac_update(&hmac_context, value, strlen(value));
		len = dtls_hmac_finalize(&hmac_context, result);
		dtls_hmac_free(&hmac_context);
		//printf("%s, %d\n",result,len);
			
		bool chunk[CHUNK_SIZE] = {false};
  		for(i = 0; i < len; ++i)
	    	{
			unsigned char cur = result[i];
			int offset = i * 8;
			int bit = 0;
			for(bit = 0; bit < 8; ++bit)
			{
				chunk[offset%CHUNK_SIZE] = cur & 1;
				++offset;   // Move to next bit in b
				if (offset%CHUNK_SIZE==0) {
					int index = bitArrayToInt32(chunk,CHUNK_SIZE);
					bf[index] = 1;
					//printf("%d\n",index);
				}
				cur >>= 1;  // Move to next bit in array
			}
			
	    	}
	}
	

}

static bool bf_compare(unsigned char* key,const unsigned char* value, bool* yourbf) {
	int i;
	unsigned char result[DTLS_HMAC_MAX];
	size_t len;
	dtls_hmac_context_t hmac_context;
	dtls_hmac_init(&hmac_context, key, 16);
	dtls_hmac_update(&hmac_context, value, strlen(value));
	len = dtls_hmac_finalize(&hmac_context, result);
	dtls_hmac_free(&hmac_context);
		
	bool chunk[CHUNK_SIZE] = {false};
	for(i = 0; i < len; ++i)
    	{
		unsigned char cur = result[i];
		int offset = i * 8;
		int bit = 0;
		for(bit = 0; bit < 8; ++bit)
		{
			chunk[offset%CHUNK_SIZE] = cur & 1;
			++offset;   // Move to next bit in b
			if (offset%CHUNK_SIZE==0) {
				int index = bitArrayToInt32(chunk,CHUNK_SIZE);
				if (yourbf[index])
					return 0;
			}
			cur >>= 1;  // Move to next bit in array
		}
		
    	}
	return 1;
}

static void toBit(unsigned char* byteArr, bool *bitArr) {
	int i;
	for(i = 0; i < BF_SIZE/8; ++i)
	{
		char cur = byteArr[i];
		int offset = i * CHAR_BIT;
		int bit;
		for(bit = 0; bit < CHAR_BIT; ++bit)
		{
		    bitArr[offset] = cur & 1;
		    ++offset;   // Move to next bit in b
		    cur >>= 1;  // Move to next bit in array
		}
	}
}

static size_t toByte(bool* bf,unsigned char* buf) {
	int i,j;
	for (i=0;i<BF_SIZE/8;i++) {
		unsigned char c = 0;
		for (j=0; j < 8; ++j) {
			if (bf[j+i*8])
			    c |= 1 << j;
		}
		buf[i] = c;
	}
	
	return 128;
}

static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
RESOURCE(res_bf,
         "title=\"Hello world: ?len=0..\";rt=\"Text\"",
         res_get_handler,
         NULL,
         NULL,
         NULL);

/*-------------------------------------------------------------------------------------------------------*/
static void
res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{ 
char json_msg[90];
if(*offset == 0) {
	//printf("incoming data\n");
	const uint8_t *payload = 0;
  	int pay_len = REST.get_request_payload(request, &payload);
	coap_packet_t *packet = (coap_packet_t *)request;
        printf("len = %d,num= %d,offset=%d\n",pay_len,packet->block1_num,packet->block1_offset);
	uint32_t i;
	//printf("\npayload: %s\n",payload);
    /* Incoming Data */
    if(coap_block1_handler(request, response, big_msg, &big_msg_len, MAX_DATA_LEN, current_token, &block_list, &fin)) {
      /* More Blocks will follow. Example waits for
       * the last block and stores data into big_msg. */ 
	
      return;
    }
    /* Last block was received. */
    //coap_separate_accept(request, &request_metadata);
    printf("big msg len %d\n",big_msg_len);

    static struct jsonparse_state parser;
    //const char json_string2[] = "{\"userid\": \"Tam Le\", \"bf\": \"something\"}";
    jsonparse_setup(&parser, big_msg, big_msg_len);
    printf("big msg: %s\n",big_msg);
    //jsonparse_setup(&parser, json_string2, 39);
    int type;
    size_t len;
    //unsigned char userid[20];
    static unsigned char decoded_bf[128];
    unsigned char action[20];
    unsigned short c1;
    while((type = jsonparse_next(&parser)) != 0) {
		//printf("type = %c\n",type);
	    if(type == JSON_TYPE_PAIR_NAME) {
	      if(jsonparse_strcmp_value(&parser, "userid") == 0) { printf("parse userid\n");
		jsonparse_next(&parser);
		jsonparse_copy_value(&parser, userid, 20);printf("userid = %s\n",userid);
	      } else if(jsonparse_strcmp_value(&parser, "bf") == 0) {
		printf("parse bf\n");
		jsonparse_next(&parser);
		char encoded_bf[200];
		jsonparse_copy_value(&parser, encoded_bf, 200);
		len = base64_decode(encoded_bf,decoded_bf);
 		printf("%s\n",encoded_bf);
		} else if (jsonparse_strcmp_value(&parser, "action") == 0) {
			printf("parse action\n");
			jsonparse_next(&parser);
			jsonparse_copy_value(&parser, action, 20);printf("action = %s\n",action);
		} else if (jsonparse_strcmp_value(&parser, "challenge") == 0) {printf("parse challenge\n");
			jsonparse_next(&parser);
			c1 = jsonparse_get_value_as_int(&parser);printf("challenge = %u\n",c1);
		}
	    }
    }  
    
    random_init(789);
  
    /* Need Time for calculation now */
	
    if (len==128){
	// create bloom filter
	bool bf[BF_SIZE] = {false};
	bool yourbf[BF_SIZE] = {false};
	toBit(decoded_bf,yourbf);
	bf_add(keys,12,"Full control",bf);
	char xor_result[strlen(userid)];
	xor_func(userid,c1,xor_result);
	bf_add(&keys[0],1,xor_result,bf);
	uint8_t count = 0;
	bool ok = 0;
	if (!strcmp(action,"Full control"))
	{
		if (!memcmp(yourbf,bf,BF_SIZE)) ok = 1;
	}
	else if (!strcmp(action,"Modify"))
	{
		int i;	
		for (i=0;i<12;i++) {
			if (bf_compare(keys[i],action,yourbf)) {
				count++;
				bf_add(&keys[i],1,action,bf);
			}
		}
		if ((count>=6) && !memcmp(yourbf,bf,BF_SIZE))
			ok = 1;
	}
	else if (!strcmp(action,"Notification"))
	{
		int i;	
		int key_idx[12];
		for (i=0;i<12;i++) {
			if (bf_compare(keys[i],"Modify",yourbf)) {
				key_idx[count] = i;
				count++;
				bf_add(&keys[i],1,"Modify",bf);
			}
		}
		if ((count>=6) && !memcmp(yourbf,bf,BF_SIZE))
		{
			int count2 = 0;
			for (i=0;i<count;i++) {
				if (bf_compare(keys[key_idx[i]],action,yourbf)) {
					count2++;
					bf_add(&keys[i],1,action,bf);
				}
			}
			if ((count2>=3) && !memcmp(yourbf,bf,BF_SIZE)) ok = 1;
		}
	}
    	
	if (ok) {
		// create message
		c2 = random_rand();
				
		snprintf(json_msg, 90, "{\"challenge\": %u}",c2);
		printf("%s\n",json_msg);
		// first block
		//memcpy(buffer,json_msg,REST_MAX_CHUNK_SIZE);
		coap_set_payload(response,json_msg,strlen(json_msg));
		//coap_set_header_block2(response, 0, 1, REST_MAX_CHUNK_SIZE);
		coap_set_status_code(response, CONTINUE_2_31);
		printf("challenge sent\n");
		fin = 1; printf("FIN = %u\n",fin);
		
	}
	else
		coap_set_payload(response,"notmatch",8);
		//fin = 0; printf("uFIN = %u\n",fin);
    }
    else {
	printf("step2 userid: %s\n",userid);
	printf("step c2 = %u\n",c2);
	char* temp_xor;
	xor_func(userid,c2,temp_xor);
	char myhash[40];
	hash_result(keys[0],temp_xor, myhash);
	printf("my   hash: %s\n",myhash);
	printf("your hash: %s\n",payload);
	if (!memcmp(myhash,payload,20))
		coap_set_payload(response,"ok",2);
	else
		coap_set_payload(response,"access denied",13);
	fin = 0; printf("xFIN = %u\n",fin);
    } 
    //clear msg buffer
    memset(&big_msg[0], 0, sizeof(big_msg));

  } else { printf("else\n");
    /* request for more blocks */
    if(*offset >= big_msg_len) {
      coap_set_status_code(response, BAD_OPTION_4_02);
      coap_set_payload(response, "BlockOutOfScope", 15);
      return;
    }

    memcpy(buffer, json_msg+REST_MAX_CHUNK_SIZE, REST_MAX_CHUNK_SIZE);
    printf("something\n");
    
    coap_set_payload(response, buffer, REST_MAX_CHUNK_SIZE);
  }
}
 
