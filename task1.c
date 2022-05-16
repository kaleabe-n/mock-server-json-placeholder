#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg,BIGNUM * a){
    char * number_Str = BN_bn2hex(a);
    printf("%s %s",msg,number_Str);
    OPENSSL_free(number_Str);
}
int main()
{
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *d = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e,"0D88C3");

    BIGNUM *num1 = BN_new();
    BIGNUM *num2 = BN_new();
    BIGNUM *one = BN_new();
    BN_dec2bn(&one,"1");

    BN_sub(num1,p,one);
    BN_sub(num2,q,one);
    BN_mul(l,num1,num2,ctx);
    BN_mod_inverse(d,e,l,ctx);

    printBN("the generated private key is ",d);

    return 0;
}
