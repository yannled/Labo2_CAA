//
// Created by zutt on 4/20/19.
//

#include "Crypto.h"

//CONSTANTES
#define OPS_HASH_PASSWORD crypto_pwhash_OPSLIMIT_MODERATE*10
#define MEM_HAHS_PASSWORD crypto_pwhash_MEMLIMIT_MODERATE*10

int getPasswordHash(const char *password, char *outHash) {
    int dwLength = strlen(password);
    return crypto_pwhash_str(outHash, password, dwLength, crypto_pwhash_OPSLIMIT_MODERATE*5, crypto_pwhash_MEMLIMIT_MODERATE*5);
}

int verifyHash(char *hash, char *password) {
    return crypto_pwhash_str_verify(hash, password, strlen(password));
}

int encryptKeyWithKey(const unsigned char *keyToEncrypt,long long lenKeyToEncrypt, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                      unsigned long long* resultLen) {
    randombytes_buf(nonce, sizeof(nonce));
    return crypto_aead_chacha20poly1305_encrypt(result, resultLen, keyToEncrypt, lenKeyToEncrypt,NULL,0,NULL,nonce,key);
}

int decryptKeyWithKey(const unsigned char *keyToDecrypt,long long lenKeyToDecrypt, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                      unsigned long long* resultLen) {
    return crypto_aead_chacha20poly1305_decrypt(result, resultLen,NULL,keyToDecrypt,lenKeyToDecrypt,NULL,0,nonce,key);
}

int encryptPasswordWithKey(const unsigned char *password,long long passwordLength, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                           unsigned long long* resultLen) {

    unsigned char* encodedPassword;
    unsigned long long encodedLength;
    encodedPassword = base64_encode(password,passwordLength,&encodedLength);
    int status = encryptKeyWithKey(encodedPassword,encodedLength,key,nonce,result,resultLen);
    free(encodedPassword);
    return status;
}

int decryptPasswordWithKey(const unsigned char *encryptedPassword,long long encryptedPasswordLength, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                           unsigned long long* resultLen) {
    unsigned char encodedPassword[512];
    unsigned long long encodedLength;
    unsigned char* temp;
    int status = decryptKeyWithKey(encryptedPassword,encryptedPasswordLength,key,nonce,encodedPassword,&encodedLength);
    temp = base64_decode(encodedPassword,encodedLength,resultLen);
    strcpy(result,temp);
    free(temp);
    return status;
}