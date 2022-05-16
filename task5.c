#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a){
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg,number_str);
  OPENSSL_free(number_str);
}

int main(){
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *message = BN_new();
  BIGNUM *sign = BN_new();
  BIGNUM *signDec = BN_new();
  BN_CTX *ctx = BN_CTX_new(); 

  BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&e,"010001");
  BN_hex2bn(&message,"4c61756e63682061206d697373696c652e");
  BN_hex2bn(&sign,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  
  printBN("the hex value of the message is ",message);

  BN_mod_exp(signDec,sign,e,n,ctx);
  printBN("the signiture decripted is ",signDec);

  return 0;
}