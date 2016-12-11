#include "tinydtls.h"
#include "dtls_config.h"
#include "hmac.h"
#include <stdbool.h>

#define BF_SIZE 1024
#define CHUNK_SIZE 10
#define CHAR_BIT 8
#define NUM_KEY 16
#define KEY_LENGTH 10

void xor_func(const char* , int , char* );
void hash_result(const char* ,const char* , char* );
int bitArrayToInt32(bool[], int );

void bf_add(unsigned char**, int , int,const unsigned char* , bool* );
size_t toByte(bool* ,unsigned char* );
