#include "coap.h"
#include "coap_list.h"
//#include "coap_config.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <bitset>
#include <openssl/hmac.h>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "json/json.h"

#define BF_SIZE 1024
#define CHUNK_SIZE 10
#define SHA_DIGEST_LENGTH 20
#define NUM_KEY 16

using namespace std;

bitset<BF_SIZE> bf;
string userid;
//int challenge;
string keys[NUM_KEY];

static coap_uri_t uri;

std::string random_string( size_t length )
{
    auto randchar = []() -> char
    {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

void bf_add(string* keys, int numkey, string value) {
	for (int j = 0;j < numkey;j++) {
		unsigned char* result;
		unsigned int len = 20;
		result = (unsigned char*)malloc(sizeof(char) * SHA_DIGEST_LENGTH);

		HMAC_CTX ctx;
		HMAC_CTX_init(&ctx);

		// Using sha1 hash engine here.
		// You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
		HMAC_Init_ex(&ctx, keys[j].c_str(), strlen(keys[j].c_str()), EVP_sha1(), NULL);
		HMAC_Update(&ctx, (unsigned char*)value.c_str(), strlen(value.c_str()));
		HMAC_Final(&ctx, result, &len);
		HMAC_CTX_cleanup(&ctx);
	
		bitset<CHUNK_SIZE> chunk;
	
		for(int i = 0; i < SHA_DIGEST_LENGTH; ++i)
	    	{
			unsigned char cur = result[i];
			int offset = i * 8;

			for(int bit = 0; bit < 8; ++bit)
			{
				//cout << offset << " ";
				//b[offset] = cur & 1;
				chunk[offset%CHUNK_SIZE] = cur & 1;
				++offset;   // Move to next bit in b
				if (offset%CHUNK_SIZE==0) {
					unsigned long index = chunk.to_ulong();
					bf[index] = 1;
					//cout << index << " " << chunk << endl;
				}
				cur >>= 1;  // Move to next bit in array
			}
	    	}
	}
	

}


string xor_func(string s1, int s2)
{
	string result = "";
	for (int temp = 0; temp < s1.size(); temp++){
  		result += s1[temp] ^ (s2+ temp) % 255;
 	}
	return result;
}

string hash_result(string key,string value) {
	unsigned int len = 20;
	unsigned char* digest = (unsigned char*)malloc(sizeof(char) * SHA_DIGEST_LENGTH);
	HMAC_CTX hctx;
	HMAC_CTX_init(&hctx);
	// Using sha1 hash engine here.
	// You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
	HMAC_Init_ex(&hctx, key.c_str(), strlen(key.c_str()), EVP_sha1(), NULL);
	HMAC_Update(&hctx, (unsigned char*)value.c_str(), strlen(value.c_str()));
	HMAC_Final(&hctx, digest, &len);
	HMAC_CTX_cleanup(&hctx);
	char mdString[20];
	for(int i = 0; i < 20; i++)
		 sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	string myhash(mdString);
	return myhash;
}

/*
 * The response handler
 */ 
static void
message_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface, 
                const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received, 
                const coap_tid_t id) 
{
	unsigned char* data;
	size_t         data_len;
	//cout << received->hdr->code << endl;
	//if (COAP_RESPONSE_CLASS(received->hdr->code) == 2) 
	switch (received->hdr->code) {

		case COAP_RESPONSE_CODE(201):
		{	//cout << COAP_RESPONSE_CODE(201) << endl;
			if (coap_get_data(received, &data_len, &data))
			{
				Json::Value jsonObj;
				Json::Reader reader;
				bool parsingSuccessful = reader.parse(data, jsonObj);
				if (parsingSuccessful) {
					int challenge2 = jsonObj["challenge"].asInt();
					string yourhash = jsonObj["hash"].asString();
					int lastbit = jsonObj["lastbit"].asInt();
					//cout << yourhash << endl;
					//cout << challenge2 << endl;

					string myhash = hash_result(keys[1],xor_func(userid,challenge2));
					if ((myhash==yourhash) && bf.test(lastbit)) {
						string myhash2 = hash_result(keys[2],xor_func(userid,challenge2));
						cout << myhash2 << endl;
						Json::Value fromScratch;
						fromScratch["step"] = 2;
						fromScratch["hash"] = myhash2;
						Json::FastWriter fastWriter;
						std::string jsonMessage = fastWriter.write(fromScratch);
						/* create pdu with request for next block */
						coap_pdu_t *pdu            = coap_new_pdu();	
						pdu->hdr->type = COAP_MESSAGE_CON;
						pdu->hdr->id   = coap_new_message_id(ctx);
						pdu->hdr->code = 3;
						coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
						//const char* hello     = "Hello2";
						coap_add_data(pdu,strlen(jsonMessage.c_str()),(unsigned char *)jsonMessage.c_str());
						coap_send_confirmed(ctx, ctx->endpoint, remote, pdu);
						//coap_delete_pdu(pdu);
						fd_set            readfds; 
						FD_ZERO(&readfds);
						FD_SET( ctx->sockfd, &readfds );
				
						int result = select( FD_SETSIZE, &readfds, 0, 0, NULL );
						if ( result < 0 ) /* socket error */
						{
							exit(EXIT_FAILURE);
						} 
						else if ( result > 0 && FD_ISSET( ctx->sockfd, &readfds )) /* socket read*/
						{	 
								coap_read( ctx );       
						} 
					}
				}
			}
		}
		break;
		
		case COAP_RESPONSE_CODE(203):
			cout << "ok" << endl;
			break;
		case COAP_RESPONSE_CODE(403):
			cout << "Unauthorized request" << endl;
			break;
	}
}



int main(int argc, char* argv[])
{
	int opt;
	string action;
	FILE * pFile;
	while ((opt = getopt(argc, argv, "u:a:k:")) != -1) {
		switch (opt) {
			case 'u' :
				userid.assign(optarg,strlen(optarg));
				break;
			case 'a' :
				action.assign(optarg,strlen(optarg));
				break;
			case 'k' :
				pFile = fopen (optarg,"r");
				break;
			default:
				//usage( argv[0], PACKAGE_VERSION );
				exit( 1 );
		}
	}
	// load keys
	int i = 0;
	char line[20];
	while (1) {
		if (fgets(line,20, pFile) == NULL) break;
		line[strcspn(line, "\n")] = 0; // remove \n
		keys[i] = line;
		//cout << i << ": " << keys[i] << endl;
		i++;
	}

	// create bloom filter
	bf_add(keys,NUM_KEY,action);
	int challenge = rand();
	bf_add(&keys[1],1,xor_func(userid,challenge));

	

	// create json
	Json::Value fromScratch;
	fromScratch["step"] = 1;
	fromScratch["bloom"] = bf.to_string();
	fromScratch["userid"] = userid;
	fromScratch["action"] = action;
	fromScratch["challenge"]= challenge;

	// write in a nice readible way
	//Json::StyledWriter styledWriter;
	//std::cout << styledWriter.write(fromScratch);

	// ---- parse from string ----

	// write in a compact way
	Json::FastWriter fastWriter;
	std::string jsonMessage = fastWriter.write(fromScratch);

	coap_context_t*   ctx;
	coap_address_t    dst_addr, src_addr;
	
	fd_set            readfds; 
	coap_pdu_t*       request;
	//const unsigned char* server_uri = reinterpret_cast<const unsigned char *>( "coap://127.0.0.1/hello" );
	const char*       server_uri = "coap://127.0.0.1/hello";
	unsigned char     put_method = 3;
	/* Prepare coap socket*/
	coap_address_init(&src_addr);
	src_addr.addr.sin.sin_family      = AF_INET;
	src_addr.addr.sin.sin_port        = htons(0);
	src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
	ctx = coap_new_context(&src_addr);
	/* The destination endpoint */
	coap_address_init(&dst_addr);
	dst_addr.addr.sin.sin_family      = AF_INET;
	dst_addr.addr.sin.sin_port        = htons(5683);
	dst_addr.addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	/* Prepare the request */
	coap_split_uri(server_uri, strlen(server_uri), &uri);
	request            = coap_new_pdu();	
	request->hdr->type = COAP_MESSAGE_CON;
	request->hdr->id   = coap_new_message_id(ctx);
	request->hdr->code = put_method;
	coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
	coap_add_data(request,strlen(jsonMessage.c_str()),jsonMessage.c_str());
	/* Set the handler and send the request */
	coap_register_response_handler(ctx, message_handler);
	coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
	//coap_delete_pdu(request);
	FD_ZERO(&readfds);
	FD_SET( ctx->sockfd, &readfds );
	int result = select( FD_SETSIZE, &readfds, 0, 0, NULL );
	if ( result < 0 ) /* socket error */
	{
		exit(EXIT_FAILURE);
	} 
	else if ( result > 0 && FD_ISSET( ctx->sockfd, &readfds )) /* socket read*/
	{	 
			coap_read( ctx );       
	} 
  return 0;
}
