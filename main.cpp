#include "sym_enc_dec.h"
#include <iostream>
using namespace std;

Symmetric_aes sym_obj;

int main(int argc, char** argv)
{


    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";
    unsigned char plaintext[] = "Ubuntu";

    sym_obj.MySSLInit();

    std::cout<<"Secure line connected. Sending box sign on in."<<endl;
	std::cout<<"INIT ENC"<<std::endl;
	sym_obj.encrypt_EVP_aes_256_gcm_init(sym_obj.vps_ctx,key,iv);
	sym_obj.decrypt_EVP_aes_256_gcm_init(sym_obj.vps_ctx,key,iv);

 std::cout<<"sss"<<endl;

    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
	int decryptedtext_len = 0, ciphertext_len = 0;
 std::cout<<"sss2"<<endl;
    sym_obj.encrypt(sym_obj.vps_ctx,plaintext,sizeof(plaintext),ciphertext,&ciphertext_len);
			

	return 0;
}