//
// Created by zutt on 4/20/19.
//

#ifndef PASSWORDMANAGER_CRYPTO_H
#include <sodium.h>
#include <string.h>
#include "base64.h"
#define PASSWORDMANAGER_CRYPTO_H

int getPasswordHash(const char* password, char* outHash);

int verifyHash(char* hash, char* password);

int encryptKeyWithKey(const unsigned char *keyToEncrypt,long long lenKeyToEncrypt, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                      unsigned long long* resultLen);

int decryptKeyWithKey(const unsigned char *keyToDecrypt,long long lenKeyToDecrypt, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                      unsigned long long* resultLen);

int encryptPasswordWithKey(const unsigned char *password,long long passwordLength, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                           unsigned long long* resultLen);

int decryptPasswordWithKey(const unsigned char *encryptedPassword,long long encryptedPasswordLength, const unsigned char *key, unsigned char* nonce, unsigned char* result,
                           unsigned long long* resultLen);


#endif //PASSWORDMANAGER_CRYPTO_H
