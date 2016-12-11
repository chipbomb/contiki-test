#include "base64.h"
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <cstring>

int main() {
  const std::string s = "ADP GmbH\nAnalyse Design" ;
  char temp[200];
  printf("s len = %d\n",s.length());
  int len = base64_encode(reinterpret_cast<const unsigned char*>(s.c_str()), s.length(), temp);
  printf("after encoded len = %d\n",len);
  char encoded[len];
  memcpy(encoded,temp,len+1);
  char decoded[len];
  len = base64_decode(encoded,decoded);

  printf("encoded: %s\n",encoded);
  std::cout << "decoded: " << decoded << std::endl;

  return 0;
}
