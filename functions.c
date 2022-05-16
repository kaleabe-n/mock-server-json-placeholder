#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256
void printBN(char *msg, BIGNUM * a){
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n",msg,number_str);
    OPENSSL_free(number_str);
}

int main(){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();
    
    BN_CTX *ctx = BN_CTX_new()

    BIGNUM *a = BN_new()

    // Assign a value from a decimal number string
    BN_dec2bn(&a, "12345678901112231223");
    // Assign a value from a hex number string
    BN_hex2bn(&a, "2A3B4C55FF77889AED3F");
    // Generate a random number of 128 bits
    BN_rand(a, 128, 0, 0);
    // Generate a random prime number of 128 bits
    BN_generate_prime_ex(a, 128, 1, NULL, NULL, NULL);


    BN_sub(res, a, b);
    BN_add(res, a, b);

    BN_mul(res, a, b, ctx)

    Compute res = a ∗ b mod n:
    BN_mod_mul(res, a, b, n, ctx)

     Compute res = a pow c mod n:
    BN_mod_exp(res, a, c, n, ctx)


    Compute modular inverse, i.e., given a, find b, such that a ∗ b mod n = 1. The value b is called
    the inverse of a, with respect to modular n.
    BN_mod_inverse(b, a, n, ctx);




    BN_generate_prime_ex(a, NBITS, 1,NULL, NULL, NULL);
    BN_dec2bn()
    BN_dec2bn(&b, "273489463796838501848592769467194369268");
    BN_rand(n, NBITS, 0, 0);
    // res = a*b
    BN_mul(res, a, b, ctx);
    printBN("a * b = ", res);
    // res = aˆb mod n
    BN_mod_exp(res, a, b, n, ctx);
    printBN("aˆc mod n = ", res);
    return 0;
}