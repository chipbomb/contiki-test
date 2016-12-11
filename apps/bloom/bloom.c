#include "bloom.h"
void xor_func(const char* s1, int s2, char* result)
{
	int temp;
	for (temp = 0; temp < strlen(s1); temp++){
  		result[temp] = s1[temp] ^ (s2+ temp) % 255; //printf("%d\n",result[temp]);
 	}//printf("\n");
	//return result;
}

void hash_result(const char* key,const char* value, char* result) {
	unsigned int len = 20;
	unsigned char digest[DTLS_HMAC_MAX];
	dtls_hmac_context_t hmac_context;	
	dtls_hmac_init(&hmac_context, key, KEY_LENGTH);
	dtls_hmac_update(&hmac_context, value, strlen(value));
	len = dtls_hmac_finalize(&hmac_context, digest);
	dtls_hmac_free(&hmac_context);
	int i;
	for(i = 0; i < 20; i++)
	sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);
}

int bitArrayToInt32(bool arr[], int count)
{
    int ret = 0; int i;
    int tmp;
    for (i = 0; i < count; i++) {
        tmp = arr[i];
        ret |= tmp << (count - i - 1);
    }
    return ret;
}

void bf_add(unsigned char* keys[], int numkey, int key_length, const unsigned char* value, bool* bf) {
	int i,j;	
	for (j = 0;j < numkey;j++) {
		unsigned char result[DTLS_HMAC_MAX];
		size_t len;
		//const unsigned char temp[] = "abcde";
		//printf("start hash\n");
		dtls_hmac_context_t hmac_context;
		dtls_hmac_init(&hmac_context, keys[j], key_length);
		dtls_hmac_update(&hmac_context, value, strlen(value));
		len = dtls_hmac_finalize(&hmac_context, result);
		dtls_hmac_free(&hmac_context);
		//printf("finish hash\n");
		//printf("%s, %d\n",result,len);
			
		bool chunk[CHUNK_SIZE] = {false};
  		for(i = 0; i < len; ++i)
	    	{
			unsigned char cur = result[i];
			int offset = i * 8;
			int bit = 0;
			for(bit = 0; bit < 8; ++bit)
			{
				//cout << offset << " ";
				//b[offset] = cur & 1;
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

void bf_add_derived(unsigned char* keys[], int numkey, const unsigned char* value,int n, const unsigned char* id, bool* bf) {
	int i,j;
	//printf("start add\n");
	for (j = 0;j < numkey;j++) {
		unsigned char result[DTLS_HMAC_MAX];
		size_t len;//printf("1\n");
		//const unsigned char temp[] = "abcde";
		//printf("start hash\n");
		dtls_hmac_context_t hmac_context;
		dtls_hmac_init(&hmac_context, keys[j], KEY_LENGTH);
		//char temp[30];
		//sprintf(temp,"%s%d%s",value,n,id);
		//dtls_hmac_update(&hmac_context, temp, strlen(temp));
		dtls_hmac_update(&hmac_context, value, strlen(value));
		char temp[3];
		sprintf(temp,"%d",n);
		dtls_hmac_update(&hmac_context, temp, strlen(temp));
		dtls_hmac_update(&hmac_context, id, strlen(id));
		dtls_hmac_update(&hmac_context, value, strlen(value));
		len = dtls_hmac_finalize(&hmac_context, result);
		dtls_hmac_free(&hmac_context);
		//printf("%s, %d\n",result,len);
		//printf("finish hash\n");
		bool chunk[CHUNK_SIZE] = {false};
  		for(i = 0; i < len; ++i)
	    	{
			unsigned char cur = result[i];
			int offset = i * 8;
			int bit = 0;
			for(bit = 0; bit < 8; ++bit)
			{
				//cout << offset << " ";
				//b[offset] = cur & 1;
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
	//printf("finish add\n");

}

bool bf_compare(unsigned char* key,int key_length,const unsigned char* value, bool* yourbf) {
	int i;
	unsigned char result[DTLS_HMAC_MAX];
	size_t len;
	dtls_hmac_context_t hmac_context;
	dtls_hmac_init(&hmac_context, key, key_length);
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
				int index = bitArrayToInt32(chunk,CHUNK_SIZE);//printf("%d\n",index);
				if (!yourbf[index])
					return 0;
			}
			cur >>= 1;  // Move to next bit in array
		}
		
    	}
	return 1;
}

bool bf_compare_derived(unsigned char* key,int key_length,const unsigned char* value, int n, const unsigned char* id,bool* yourbf) {
	int i;
	unsigned char result[DTLS_HMAC_MAX];
	size_t len;//printf("1\n");
	//const unsigned char temp[] = "abcde";
	printf("start hash\n");
	dtls_hmac_context_t hmac_context;
	dtls_hmac_init(&hmac_context, key, KEY_LENGTH);
	dtls_hmac_update(&hmac_context, value, strlen(value));
	char temp[3];
	sprintf(temp,"%d",n);
	dtls_hmac_update(&hmac_context, temp, strlen(temp));
	dtls_hmac_update(&hmac_context, id, strlen(id));
	dtls_hmac_update(&hmac_context, value, strlen(value));
	len = dtls_hmac_finalize(&hmac_context, result);
	dtls_hmac_free(&hmac_context);
	printf("finish hash\n");
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
				int index = bitArrayToInt32(chunk,CHUNK_SIZE);//printf("%d\n",index);
				if (!yourbf[index])
					return 0;
			}
			cur >>= 1;  // Move to next bit in array
		}
		
    	}
	return 1;
}

int bf_add_compare_derived(unsigned char* key,int key_length,const unsigned char* value, int n, const unsigned char* id,bool* yourbf,bool* mybf) {
	int i;
	unsigned char result[DTLS_HMAC_MAX];
	size_t len;//printf("1\n");
	//const unsigned char temp[] = "abcde";
	//printf("start hash\n");
	dtls_hmac_context_t hmac_context;
	dtls_hmac_init(&hmac_context, key, KEY_LENGTH);
	dtls_hmac_update(&hmac_context, value, strlen(value));
	char temp[3];
	sprintf(temp,"%d",n);
	dtls_hmac_update(&hmac_context, temp, strlen(temp));
	dtls_hmac_update(&hmac_context, id, strlen(id));
	dtls_hmac_update(&hmac_context, value, strlen(value));
	len = dtls_hmac_finalize(&hmac_context, result);
	dtls_hmac_free(&hmac_context);
	//printf("finish hash\n");
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
				int index = bitArrayToInt32(chunk,CHUNK_SIZE);//printf("%d\n",index);
				if (!yourbf[index])
					return 0;
				else
					mybf[index] = 1;
			}
			cur >>= 1;  // Move to next bit in array
		}
		
    	}
	return 1;
}


void get_derived_key(unsigned char *key,const unsigned char* value,int n, const unsigned char* id, unsigned char *derived_key)
{
	size_t len;
	dtls_hmac_context_t hmac_context;
	dtls_hmac_init(&hmac_context, key, KEY_LENGTH);
	dtls_hmac_update(&hmac_context, value, strlen(value));
	char temp[3];
	sprintf(temp,"%d",n);
	dtls_hmac_update(&hmac_context, temp, strlen(temp));
	dtls_hmac_update(&hmac_context, id, strlen(id));
	len = dtls_hmac_finalize(&hmac_context, derived_key);
	dtls_hmac_free(&hmac_context);
}

void get_ver_ticket(unsigned char *keys[],int num_key,const unsigned char* value,int n, const unsigned char*id, unsigned char *t, unsigned char *ver_ticket) {

	size_t len;
	int i;
	unsigned char digest[DTLS_HMAC_MAX];
	dtls_hmac_context_t hmac_context;
	dtls_hmac_init(&hmac_context, keys[0], KEY_LENGTH);
	for (i=1;i<num_key;i++) {		
		dtls_hmac_update(&hmac_context, keys[i], KEY_LENGTH);
	}
	dtls_hmac_update(&hmac_context, value, strlen(value));
	char temp[3];
	sprintf(temp,"%d",n);
	dtls_hmac_update(&hmac_context, temp, strlen(temp));
	dtls_hmac_update(&hmac_context, id, strlen(id));
	dtls_hmac_update(&hmac_context, t, strlen(t));
	len = dtls_hmac_finalize(&hmac_context, digest);
	dtls_hmac_free(&hmac_context);
	for(i = 0; i < 20; i++)
	sprintf(&ver_ticket[i*2], "%02x", (unsigned int)digest[i]);
}

size_t toByte(bool* bf,unsigned char* buf) {
	//unsigned char buf[BF_SIZE/8]="";
	//printf("%d\n",strlen(buf));
	int i,j;
	for (i=0;i<BF_SIZE/8;i++) {
		unsigned char c = 0;
		for (j=0; j < 8; ++j) {
			if (bf[j+i*8])
			    c |= 1 << j;
		}
		//printf("%d, %d \n",i,c);
		buf[i] = c;
		//buf[i] = i+100;
		//printf("%d\n",buf[i]);
	}
	//printf("\n");
	//printf("size %d\n", strlen(buf));
	return 128;
}

char* random_string( size_t length )
{
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    char result[length];
    int i;
    for (i=0;i<length;i++)
	result[i] = charset[random_rand()%strlen(charset)];
    result[i] = '\0';
    return result;
}

void toBit(unsigned char* byteArr, bool *bitArr) {
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
