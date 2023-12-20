#pragma once


//OPEN SSL LIB Include
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <iostream>

/* Path for CA certificate */
//#define CA_FILE_PATH "../gr_cafo_cert1.pem"
//#define CA_FILE_DIR NULL
//symmetric cryptography AES 256 bits GCM mode
class Symmetric_aes
{
private:
    //char Cryptographic_key[32] {};
    //char Cryptographic_Vector[16] {};
   
   

public:
    const char * CA_FILE_PATH;
    EVP_CIPHER_CTX *vps_ctx;
    SSL_CTX *ctx;
    SSL *vishwassl;
    void UpdateCA_Path(std::string path);
    void MySSLInit();
    void ValidateCA();
    void encrypt_EVP_aes_256_gcm_init(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv);
    void encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int *ciphertext_len);

    void decrypt_EVP_aes_256_gcm_init(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv);
    void decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len);
    
};