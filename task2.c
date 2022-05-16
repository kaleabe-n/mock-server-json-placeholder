#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg,BIGNUM * a){
    char * number_Str = BN_bn2hex(a);
    printf("%s %s",msg,number_Str);
    OPENSSL_free(number_Str);
}

int main()
{
    BIGNUM *m = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m,"4120746f702073656372657421");
    BN_hex2bn(&e,"010001");
    BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BN_mod_exp(end,m,e,n,ctx);
    printBN("the encrypted message is ",enc);

    BN_mod-exp(dec,end,d,n,ctx);
    printBN("the decrypted message is (decrypting the above result) ",dec);

    return 0;
}
