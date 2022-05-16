#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a){
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg,number_str);
  OPENSSL_free(number_str);
}
int main(){
  BIGNUM *d = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *original = BN_new();
  BIGNUM *altered = BN_new();
  BIGNUM *originalSign = BN_new();
  BIGNUM *alteredSign = BN_new();
  BN_CTX *ctx = BN_CTX_new(); 

  BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  BN_dec2bn(&original,"Ioweyou$2000");
  BN_dec2bn(&altered,"Ioweyou$3000");
  
  BN_mod_exp(originalSign,original,d,n,ctx);
  printBN("the original message's signiture is ",originalSign);

  BN_mod_exp(alteredSign,altered,d,n,ctx);
  printBN("the altered message's signiture is  ",alteredSign);

  return 0;
}