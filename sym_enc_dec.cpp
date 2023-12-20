#include "sym_enc_dec.h"
#include <string.h>
//static Symmetric_aes obj;

/*Symmetric_aes object_return()
{
    return obj;
}
*/
using namespace std;
void Symmetric_aes::UpdateCA_Path(std::string path)
{
    //should have taken char array in starting anyway will change this if time allow
    char * ch = new char[path.length() + 1];
    strcpy(ch, path.c_str());
    CA_FILE_PATH = ch; 
}
void Symmetric_aes::MySSLInit()
{

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();    


}

void Symmetric_aes::encrypt_EVP_aes_256_gcm_init(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv)
{

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
       std::cout << "EVP CIPHER FAILED: " << "ERROR" << std::endl;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
    {
      std::cout << "EVP EncryptINIT FAILED: " << "ERROR" << std::endl;
    }

}

void Symmetric_aes ::encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int *ciphertext_len)
{
    int len = 0;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        
         printf("EVP_EncryptUpdate: OpenSSL error: %s", ERR_error_string(ERR_get_error(), nullptr));           
         std::cout << "EVP EncryptUpdate FAILED: " << "ERROR" << std::endl;
    }
    *ciphertext_len = len;
}

void Symmetric_aes::decrypt_EVP_aes_256_gcm_init(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv)
{
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
       std::cout << "EVP CIPHER FAILED: " << "ERROR" << std::endl;
    }
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
    {
      std::cout << "EVP DecryptInit FAILED: " << "ERROR" << std::endl;
    }
}

void Symmetric_aes::decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len)
{
    int len =0;
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        std::cout << "EVP DecryptUpdate FAILED: " << "ERROR" << std::endl;
    }
    *plaintext_len = len;
}