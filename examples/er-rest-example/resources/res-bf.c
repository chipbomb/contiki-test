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
#include "er-coap-block1_new.h"
#include "er-coap-separate.h"
#include "er-coap-transactions.h"
#include "tinydtls.h"
#include "dtls_config.h"
#include "hmac.h"
#include "jsonparse.h"
#include "base64.h"
#include "bloom.h"
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
//static const char *keys[] ={"ReB5I4WTSMohvkwg","NM5oUPgQXbYxjgk9","JtCZyi2Q4p6xZ2ev","Mjhq6NHdxnZeSJnl","CzI8gKZk9dihdMaz","3HpAd4laqIEIb01m","xHudbRMj44OhOygP","FUXqYHQOZdeBbdvY","upAUFWBJYZzuXdJk","7rZe6z0fadoBEji7","XsbkOm3uJ0ooe7Yj","w5N05Ogd1SpFAVMf"};

static const char *keys[] = {"za5UNI5ARc","1I9uF2F8tI","D8pkHSboTO","fgT03Gn2fE",
			"d6503Shmh8","ZQ50beTWPs","p2JGtaTk9y","h0nkbQtCZC",
			"5MhGv2rGbm","dc9sRYFOJu","R69QtaXUf6","tIPkHkhGXW",
			"fCJ4PuxUZO","ZmfQ3YvcxG","NEd6hKHwNe","fUhqRAZ6v8"};

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
//printf("received\n");
if(*offset == 0) {
	//printf("incoming data\n");
	const uint8_t *payload = 0;
  	int pay_len = REST.get_request_payload(request, &payload);
	coap_packet_t *packet = (coap_packet_t *)request;
        //printf("len = %d,num= %d,offset=%d\n",pay_len,packet->block1_num,packet->block1_offset);
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
    //printf("big msg len %d\n",big_msg_len);
	printf("received\n");
    static struct jsonparse_state parser;
    //const char json_string2[] = "{\"userid\": \"Tam Le\", \"bf\": \"something\"}";
    jsonparse_setup(&parser, big_msg, big_msg_len);
    //printf("big msg: %s\n",big_msg);
    //jsonparse_setup(&parser, json_string2, 39);
    int type;
    size_t len;
    //unsigned char userid[20];
    static unsigned char decoded_bf[BF_SIZE/8];
    unsigned char action[20];
    unsigned short c1;
    while((type = jsonparse_next(&parser)) != 0) {
		//printf("type = %c\n",type);
	    if(type == JSON_TYPE_PAIR_NAME) {
	      if(jsonparse_strcmp_value(&parser, "userid") == 0) { //printf("parse userid\n");
		jsonparse_next(&parser);
		jsonparse_copy_value(&parser, userid, 20);//printf("userid = %s\n",userid);
	      } else if(jsonparse_strcmp_value(&parser, "bf") == 0) {
		//printf("parse bf\n");
		jsonparse_next(&parser);
		char encoded_bf[200];
		jsonparse_copy_value(&parser, encoded_bf, 200);
		len = base64_decode(encoded_bf,decoded_bf);
 		//printf("%s\n",encoded_bf);
		} else if (jsonparse_strcmp_value(&parser, "action") == 0) {
			//printf("parse action\n");
			jsonparse_next(&parser);
			jsonparse_copy_value(&parser, action, 20);//printf("action = %s\n",action);
		} else if (jsonparse_strcmp_value(&parser, "challenge") == 0) {//printf("parse challenge\n");
			jsonparse_next(&parser);
			c1 = jsonparse_get_value_as_int(&parser);//printf("challenge = %u\n",c1);
		}
	    }
    }  
    //printf("done parsing\n");
    random_init(789);
  
    /* Need Time for calculation now */
	//printf("start step 1\n");
    if (len==128){
	// create bloom filter
	
	bool yourbf[BF_SIZE] = {false};
	toBit(decoded_bf,yourbf);
	//bf_add(keys,12,"Full control",bf);
	//char xor_result[strlen(userid)];
	//xor_func(userid,c1,xor_result);
	//bf_add(&keys[0],1,xor_result,bf);
	uint8_t count = 0;
	bool ok = 0;
	if (!strcmp(action,"Full control"))
	{
		bool mybf[BF_SIZE] = {false};
		bf_add(keys,NUM_KEY,KEY_LENGTH,"Full control",mybf);
		if (!memcmp(yourbf,mybf,BF_SIZE)) ok = 1;
	}
	else if (!strcmp(action,"Modify"))
	{
	
		int i;
		bool mybf[BF_SIZE] = {false};
		//printf("t1\n");
		bf_add_derived(keys,NUM_KEY,"Full control",123,userid,mybf);
		//printf("t2\n");
		bf_add_derived(keys,NUM_KEY,"Modify",123,userid,mybf);
		//printf("t3\n");
		//printf("%d\n",memcmp(mybf,yourbf,BF_SIZE));
		if (!memcmp(mybf,yourbf,BF_SIZE)) ok = 1;
		printf("modify, ok = %d\n", ok);
	}
	else if (!strcmp(action,"Notification"))
	{
		int i;	
		bool mybf[BF_SIZE] = {false};
		int key_idx[NUM_KEY];

		bf_add(keys,NUM_KEY,KEY_LENGTH,"Full control",mybf);
		bf_add(keys,NUM_KEY,KEY_LENGTH,"Modify",mybf);
		count=NUM_KEY;
		//printf("count=%d\n",count);
		int count2 = 0;
		if (count==NUM_KEY) {
			
			for (i=0;i<count;i++) {
				//char derived_key[40];
				//get_derived_key(keys[key_idx[i]],action,100,userid,derived_key);
				if (bf_add_compare_derived(keys[i],KEY_LENGTH,"Monitor",100,userid,yourbf,mybf) && bf_add_compare_derived(keys[i],KEY_LENGTH,action,100,userid,yourbf,mybf)) { 
					count2++;
					//bf_add_derived(&keys[i],1,action,100,userid,mybf);
					//bf_add_derived(&keys[i],1,"Monitor",100,userid,mybf);
					//printf("1\n");
				}
			}
		}
		
		if ((count2>=NUM_KEY/2) && !memcmp(yourbf,mybf,BF_SIZE)) ok =1;
		//printf("count2=%d, ok = %d\n",count2, ok);
	}
    	//printf("end step 1\n");
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
		//printf("challenge sent\n");
		fin = 1; //printf("FIN = %u\n",fin);
		
	}
	else
		coap_set_payload(response,"notmatch",8);
		//fin = 0; printf("uFIN = %u\n",fin);
		//printf("end step 2\n");
    }
    else {
	//printf("step2 userid: %s\n",userid);
	//printf("step c2 = %u\n",c2);
	char* temp_xor;
	xor_func(userid,c2,temp_xor);
	char myhash[40];
	hash_result(keys[0],temp_xor, myhash);
	//printf("my   hash: %s\n",myhash);
	//printf("your hash: %s\n",payload);
	if (!memcmp(myhash,payload,20))
		coap_set_payload(response,"ok",2);
	else
		coap_set_payload(response,"access denied",13);
	fin = 0; //printf("xFIN = %u\n",fin);
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
 
