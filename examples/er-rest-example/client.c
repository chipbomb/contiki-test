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
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "contiki.h"
#include "contiki-net.h"
#include "er-coap-engine.h"
#include "dev/button-sensor.h"
#include "tinydtls.h"
#include "dtls_config.h"
#include "hmac.h"
#include "jsontree.h"
#include "jsonparse.h"
#include "base64.h"
#include "random.h"
#include "bloom.h"
#include "er-coap-separate.h"

#define DEBUG 0
//#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
//#else
//#define PRINTF(...)
//#define PRINT6ADDR(addr)
//#define PRINTLLADDR(addr)
//#endif

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0212, 0x7402, 0x0002, 0x0202)      /* cooja2 */
//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xbbbb, 0, 0, 0, 0, 0, 0, 0x1) 
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0200, 0, 0, 0x0002)

#define LOCAL_PORT      UIP_HTONS(COAP_DEFAULT_PORT + 1)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

#define TOGGLE_INTERVAL 10
#define BF_SIZE 1024
#define CHUNK_SIZE 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

uip_ipaddr_t server_ipaddr;
static struct etimer et;
static unsigned short c1;
static unsigned short token;
static const char *keys[] ={"ReB5I4WTSMohvkwg","NM5oUPgQXbYxjgk9","JtCZyi2Q4p6xZ2ev","Mjhq6NHdxnZeSJnl","CzI8gKZk9dihdMaz","3HpAd4laqIEIb01m","xHudbRMj44OhOygP","FUXqYHQOZdeBbdvY","upAUFWBJYZzuXdJk","7rZe6z0fadoBEji7","XsbkOm3uJ0ooe7Yj","w5N05Ogd1SpFAVMf"};
static const char userid[] = "Tam Le";
/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 4
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/actuators/toggle", "battery/", "test/bf" };
#if PLATFORM_HAS_BUTTON
static int uri_switch = 0;
#endif


/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(void *response)
{
  const char *msg;

  size_t len = coap_get_payload(response, &msg);
  //printf("received|%.*s\n", len, (char *)chunk);
  if (len>0) {
	printf("received|%.*s\n", len, (char *)msg);
	unsigned short c2;
	int type;
	static struct jsonparse_state parser;
        jsonparse_setup(&parser, msg, len);
	while((type = jsonparse_next(&parser)) != 0) {
		//printf("type = %c\n",type);
	    if(type == JSON_TYPE_PAIR_NAME) {
	      if (jsonparse_strcmp_value(&parser, "challenge") == 0) {printf("parse challenge\n");
			jsonparse_next(&parser);
			c2 = jsonparse_get_value_as_int(&parser);printf("step c2 = %u\n",c2);
		}
	    }
	}
	char *temp_xor;
	xor_func(userid,c2,temp_xor);
	char myhash[40];
	hash_result(keys[0],temp_xor, myhash);//printf("my   hash: %s\n,my key: %s\n",myhash,keys[0]);
	coap_packet_t *const coap_resp = (coap_packet_t *)response;
	coap_packet_t resp[1];
	coap_init_message(resp, COAP_TYPE_CON, COAP_GET, coap_resp->mid+1);
	coap_set_header_uri_path(resp, service_urls[3]);
	coap_set_token(resp,&token,2);
	coap_set_payload(resp,myhash,strlen(myhash));
	len = coap_serialize_message(resp, uip_appdata);
	coap_send_message(&server_ipaddr, REMOTE_PORT, uip_appdata, len);
	
  }
  
}

int create_json_message(const char* userid, const char* action,  bool* bf, int challenge, char* result) {
/*	bool newbf[BF_SIZE];*/
/*	memcpy(newbf,bf,BF_SIZE);*/
/*	char xor_result[strlen(userid)];*/
/*	xor_func(userid,challenge,xor_result);*/
/*	bf_add(&keys[0],1,xor_result,newbf);*/
	unsigned char buf[128];
	size_t len =  toByte(bf,buf);
	char encoded_bf[200];
	len = base64_encode(buf,128,encoded_bf);

	snprintf(result, 256, "{\"userid\": \"%s\", \"action\": \"%s\", \"challenge\": %u, \"bf\": \"%s\"}",userid,action,challenge,encoded_bf);
	return strlen(result);
	

}


/*---------------------------------------------------------------------------*/

PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  //static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */

  SERVER_NODE(&server_ipaddr);

  /* receives all CoAP messages */
  coap_init_engine();

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

#if PLATFORM_HAS_BUTTON
  SENSORS_ACTIVATE(button_sensor);
  printf("Press a button to request %s\n", service_urls[uri_switch]);
#endif
 
//*****************************************************************************/
// CREATE FULL CONTROL PERMISSION
  int i;
  bool bf[1024] = {false};
  unsigned char action[] = "Full control";
  bf_add(keys,12,16,action,bf);

//*****************************************************************************/

  static size_t len;
  random_init(123);
  //static unsigned short c1;
  c1 = random_rand();
  static unsigned char json_string[300];
  len = create_json_message(userid,action,bf,c1,json_string);  
  len = (1+len/REST_MAX_CHUNK_SIZE)*REST_MAX_CHUNK_SIZE;
  printf("%s\n",json_string);
  
  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      printf("--Toggle timer--\n");

	static int offset = 0;
	static int payload_size = REST_MAX_CHUNK_SIZE;
	static int more_block = 1;
	static int num_block = 0;
	static int mid = 0;
	unsigned char temp[REST_MAX_CHUNK_SIZE];
	//static unsigned short token;
	token = random_rand();
	
      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      while (offset<len)

	{	
		static coap_packet_t request[1];
		if (offset+REST_MAX_CHUNK_SIZE >= len) {
			payload_size = len-offset;
			more_block = 0;
		}
		memcpy(temp,json_string+offset,payload_size);
		//for (i=0;i<payload_size;i++) printf("%c",temp[i]);printf("\n");
		offset = offset+REST_MAX_CHUNK_SIZE;
				
		coap_init_message(request, COAP_TYPE_CON, COAP_GET, mid);
		
		coap_set_header_uri_path(request, service_urls[3]);
		// Set payload and block info 
		coap_set_token(request,&token,2);
		coap_set_payload(request, temp, payload_size);
		coap_set_header_block1(request, num_block, more_block, payload_size);
		printf("token: %x,%d,%d,%d\n",token,num_block,more_block,payload_size);
		num_block++;
		
		COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, client_chunk_handler);
			
		mid++;
	}
	offset = 0;
	payload_size = REST_MAX_CHUNK_SIZE;
	more_block = 1;
	num_block = 0;
	mid = 0;

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      printf("\n--Done--\n");

      etimer_reset(&et);

//#if PLATFORM_HAS_BUTTON
    } /*else if(ev == sensors_event && data == &button_sensor) {



      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, service_urls[uri_switch]);

      printf("--Requesting %s--\n", service_urls[uri_switch]);

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
                            client_chunk_handler);

      printf("\n--Done--\n");

      uri_switch = (uri_switch + 1) % NUMBER_OF_URLS;
#endif
    }*/
  }

  PROCESS_END();
}
