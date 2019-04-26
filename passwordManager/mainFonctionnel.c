#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "Crypto.h"
#include "FileManager.h"
#include "UserInteraction.h"
#include "base64.h"
#include "Strings_en.h"
//gcc main.c -lsodium

#define PASSWORD "Correct Horse Battery Staple"
#define KEY_LEN crypto_box_SEEDBYTES
#define FILE_MASTERKEY_SALT "MASTER_KEY_SALT"
#define File_GENERAL_KEY_ENCRYPTED "GENERAL_KEY"
#define File_GENERAL_KEY_ENCRYPTED_LENGTH "GENERAL_KEY_LENGTH"
#define File_GENERAL_KEY_NONCE "GENERAL_KEY_NONCE"
#define FILE_HASH_MSTER_PASSWORD "HASH_MASTER_PASSWORD"

int addingPassword(const unsigned char* key);
int getPassword(const unsigned char* key);
int verifyPasswordSpecifications(const char* password);
int erase_Memory(int numberOfElementsToErase, ...);

int main( int argc, char *argv[]) {

    //TEST SI ARGUMENT INITIALISATION
    if( argc == 2 && 0 == strcmp(argv[1],"init")){
        unsigned char generalKey[crypto_aead_chacha20poly1305_KEYBYTES];
        unsigned long long lengthMasterPassword = 11;
        char defaultMasterPassword[] = "yannMerite6";

        //1. GENERATE GENERAL KEY
        crypto_aead_chacha20poly1305_keygen(generalKey);

        //printf("general key : %s ",generalKey);
        unsigned char masterKey[KEY_LEN];
        unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
        unsigned char salt[crypto_pwhash_SALTBYTES];
        //TODO REPLACE BY MY FUNCTION
        randombytes_buf(salt, sizeof salt);
        if(crypto_pwhash(masterKey, sizeof masterKey,defaultMasterPassword,strlen(defaultMasterPassword),salt,crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                             crypto_pwhash_ALG_DEFAULT) != 0){
            writeUserString("ERRRRROR");
        }

        //2. DERIVING MASTER KEY from MASTER PASSWORD

        /*
        if(getKeyFromPassword(defaultMasterPassword,masterKey) != 0){
            writeUserString("ERROR DURING DERIVING MASTER KEY FROM MASTER PASSWORD");
            exit(1);
        }*/

        //3. ENCRYPT GENERAL KEY WITH MASTER KEY

        unsigned long long encryptedGeneralKeyLength = strlen(generalKey);
        unsigned char encryptedGeneralKey[encryptedGeneralKeyLength + crypto_aead_chacha20poly1305_ABYTES];

        if(encryptKeyWithKey(generalKey, encryptedGeneralKeyLength,masterKey,nonce,encryptedGeneralKey,&encryptedGeneralKeyLength)
        != 0){
            writeUserString("ERROR DURING ENCRYPT GENERAL KEY WITH MASTER KEY");
            exit(1);
        }
        //printf("initial key : %s ", encryptedGeneralKey);

        //4. WRITE ENCRYPTED GENERAL KEY IN FILE
        writeKeyValueInFile(File_GENERAL_KEY_ENCRYPTED,encryptedGeneralKey);

        //5. WRITE ENCRYPTED GENERAL KEY LENGTH IN FILE
        unsigned char str_encryptedGeneralKeyLength[4];
        snprintf(str_encryptedGeneralKeyLength, 4, "%d", encryptedGeneralKeyLength);
        writeKeyValueInFile(File_GENERAL_KEY_ENCRYPTED_LENGTH,str_encryptedGeneralKeyLength);

        //6. WRITE SALT FOR MASTERKEY DERIVTION
        writeKeyValueInFile(FILE_MASTERKEY_SALT,salt);

        //7. WRITE NONCE for ENCRYPTED GENERAL KEY IN FILE
        writeKeyValueInFile(File_GENERAL_KEY_NONCE,nonce);

        /*
        unsigned char nonceGet[512];
        readKeyValueFromFile("GENERAL_KEY_NONCE",nonceGet);
        unsigned char keyEncryptedGet[512];
        readKeyValueFromFile("GENERAL_KEY",keyEncryptedGet);
        unsigned char result[crypto_aead_chacha20poly1305_KEYBYTES];
        unsigned long long length;
        printf("encrypted key get : %s ", keyEncryptedGet);
        if(decryptKeyWithKey(keyEncryptedGet, sizeof keyEncryptedGet, masterKey,nonce,result,&length) != 0){
            printf(EROOR_DECRYPT_GENERALKEY);
        }
        printf("decrypted key : %s ", result);*/


        //6. CALCUL HASH OF MASTER PASSWORD
        char hashMasterPassword[512];
        getPasswordHash(defaultMasterPassword,hashMasterPassword);

        //7. WRITE MASTER PASSWORD HASH IN FILE
        writeKeyValueInFile(FILE_HASH_MSTER_PASSWORD,hashMasterPassword);

        exit(0);
    }

    // MAIN
    writeUserString(WELCOME);

    // *****************************************************************************************************************
    // * 1. AUTHENTIFICATION [LOCK]
    // *****************************************************************************************************************
    int numberOfChance = 3;
    char masterPassword[50];
    unsigned char masterPasswordHash[512];
    do {
        if(numberOfChance == 0){
            writeUserString(BAD_AUTHENTIFICATION);
            exit(1);
        }
        writeUserString(NUMBER_AUTH_PART1);
        writeUserInt(numberOfChance);
        writeUserString(NUMBER_AUTH_PART2);

        numberOfChance--;
        getUserString(masterPassword);
        readKeyValueFromFile(FILE_HASH_MSTER_PASSWORD, masterPasswordHash);
    } while (verifyHash(masterPasswordHash, masterPassword) != 0);

    // *****************************************************************************************************************
    // * 2. DERIVING MASTER KEY, DECRYPT GENEREAL KEY [UNLOCK]
    // *****************************************************************************************************************

    //  2.1 Deriving Master Key from Master password
    unsigned char masterKey[KEY_LEN];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    readKeyValueFromFile(FILE_MASTERKEY_SALT,salt);

    if(crypto_pwhash(masterKey, sizeof masterKey,masterPassword,strlen(masterPassword),salt,crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0){
        writeUserString(EROOR_DERIVING_MASTERKEY);
    }

    //  2.2 Decrypt General Key
    unsigned char generalKeyEncrypted[512];
    readKeyValueFromFile(File_GENERAL_KEY_ENCRYPTED,generalKeyEncrypted);

    // get nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    readKeyValueFromFile(File_GENERAL_KEY_NONCE,nonce);

    // get length of encrypt General Key
    unsigned char str_encryptedGeneralKeyLength[4];
    readKeyValueFromFile(File_GENERAL_KEY_ENCRYPTED_LENGTH,str_encryptedGeneralKeyLength);
    int encryptedGeneralKeyLength = atoi(str_encryptedGeneralKeyLength);

    // get General Key
    unsigned char generalKey[crypto_aead_chacha20poly1305_KEYBYTES];
    unsigned long long length;
    if(decryptKeyWithKey(generalKeyEncrypted, encryptedGeneralKeyLength, masterKey,nonce,generalKey,&length) != 0){
        writeUserString(EROOR_DECRYPT_GENERALKEY);
    }

    // *****************************************************************************************************************
    // * 3. ASK FOR ACTION [UNLOCK]
    // *****************************************************************************************************************

    bool continue_ask_action = true;
    while (continue_ask_action) {
        writeUserString(MENU);
        int actionNumber;
        while (true) {
            actionNumber = getUserInt();
            if (actionNumber >= 1 && actionNumber <= 4)
                break;
            writeUserString(MENU_ENTRY_NOT_VALID);
        }

        switch (actionNumber) {
            case 1 :
                addingPassword(generalKey);
                break;
            case 2 :
                getPassword(generalKey);
                break;
            case 3 :
                break;
            case 4 :
                continue_ask_action = false;
                //erase_Memory()
                break;
            default:
                writeUserString(MENU_ENTRY_NOT_VALID);
        }
    }

}

// *****************************************************************************************************************
// * ADDING NEW PASSWORD TO FILE
// *****************************************************************************************************************
int addingPassword(const unsigned char* key){
    char url[ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER];
    unsigned char password[ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER];
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

    writeUserString(ADDING_PASSWORD_URL);
    writeUserStringThenNumber(ADDING_PASSWORD_MAX_LENGTH_INPUT,ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER);
    getUserString(url);
    writeUserString(ADDING_PASSWORD_PASSWORD);
    writeUserStringThenNumber(ADDING_PASSWORD_MAX_LENGTH_INPUT,ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER);
    getUserString(password);


    // encrypt the password with general Key
    unsigned char encryptedPassword[512];
    unsigned long long encryptedPasswordLength;
    if(encryptPasswordWithKey(password,strlen(password),key,nonce,encryptedPassword,&encryptedPasswordLength) != 0){
        writeUserString(ADDING_PASSWORD_ERROR);
        return -1;
    }
    // store password
    writeKeyValueInFile(url,encryptedPassword);
    char nonceName[150];
    printf("nonce : %s ",nonceName);
    strcat(nonceName,url);
    strcat(nonceName,ADDING_PASSWORD_NONCE);
    writeKeyValueInFile(nonceName,nonce);

    erase_Memory(5,url,password,nonce,encryptedPassword,nonceName);
    return 0;
}

// *****************************************************************************************************************
// * GET PASSWORD FROM FILE
// *****************************************************************************************************************
int getPassword(const unsigned char* key){
    char url[ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER];
    unsigned char encryptedPassword[512];
    unsigned char password[ADDING_PASSWORD_MAX_LENGTH_INPUT_NUMBER];
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    unsigned long long passwordLength;
    writeUserString(GET_PASSWORD_URL);
    getUserString(url);

    char nonceName[150];
    strcat(nonceName,url);
    strcat(nonceName,ADDING_PASSWORD_NONCE);
    readKeyValueFromFile(nonceName,nonce);

    readKeyValueFromFile(url,encryptedPassword);
    if(encryptedPassword[0] == '\0'){
        writeUserString(GET_PASSWORD_ERROR_GETURL);
        return -1;
    }
    if(decryptPasswordWithKey(encryptedPassword,strlen(encryptedPassword),key,nonce,password,&passwordLength) != 0){
        writeUserString(GET_PASSWORD_ERROR_DECRYPTION);
        return -1;
    }
    writeUserString(GET_PASSWORD_PASSWORD);
    writeUserStringWithEndline(password);

    erase_Memory(5,url,encryptedPassword,password,nonce,nonceName);
    return 0;
}

// *****************************************************************************************************************
// * Change Master Password
// *****************************************************************************************************************
int changeMasterPassword(const unsigned char* generalKey){

    // Authentification with old password
    int numberOfChance = 3;
    char oldMasterPassword[50];
    unsigned char oldMasterPasswordHash[512];

    writeUserString(ChangePass_OldPass);
    do {
        if(numberOfChance == 0){
            writeUserString(BAD_AUTHENTIFICATION);
            exit(1);
        }
        writeUserString(NUMBER_AUTH_PART1);
        writeUserInt(numberOfChance);
        writeUserString(NUMBER_AUTH_PART2);

        numberOfChance--;
        getUserString(oldMasterPassword);
        readKeyValueFromFile(FILE_HASH_MSTER_PASSWORD, oldMasterPasswordHash);
    } while (verifyHash(oldMasterPasswordHash, oldMasterPassword) != 0);

    char newMasterPassword1[50];
    char newMasterPassword2[50];
    bool newPassOK = true;
    // Type new Password
    do {
        writeUserString(ChangePass_NewPass1);
        writeUserString(ChangePass_limitation);

        getUserString(newMasterPassword1);

        writeUserString(ChangePass_NewPass2);

        getUserString(newMasterPassword2);

        if(strcmp(newMasterPassword1,newMasterPassword2) != 0){
            writeUserString(ChangePass_NotSame);
            newPassOK = false;
        }

        if(verifyPasswordSpecifications(newMasterPassword1) != 0){
            writeUserString(ChangePass_NotConform);
            writeUserString(ChangePass_limitation);
            newPassOK = false;
        }

    }while (!newPassOK);

    // Erase old password Hash from file.
    // TODO

    // Add new password Hash in the file.
    char hashMasterPassword[512];
    getPasswordHash(newMasterPassword1,hashMasterPassword);

    writeKeyValueInFile(FILE_HASH_MSTER_PASSWORD,hashMasterPassword);

    // Erase old Encrypted GeneralKey in the file
    // TODO

    // Encrypt General Key with new Master Password and add it to the file.
}

int verifyPasswordSpecifications(const char* password){
    bool passwordContainMaj = false;
    bool passwordContainNumber = false;
    bool sizeIsOK = false;

    if(strlen(password) >= 10 && strlen(password) <= 50)
        sizeIsOK = true;

    for (int i = 0; i < strlen(password); ++i) {
        if(isdigit(password[i]))
            passwordContainNumber = true;

        if(isupper(password[i]))
            passwordContainMaj = true;
    }

    if(passwordContainMaj && passwordContainNumber && sizeIsOK){
        return 0;
    }
    else
        return -1;
}

// *****************************************************************************************************************
// * Erase Memory
// *****************************************************************************************************************
int erase_Memory(int numberOfElementsToErase, ...){
    va_list valist;
    va_start(valist,numberOfElementsToErase);
    /* access all the arguments assigned to valist */
    for (int i = 0; i < numberOfElementsToErase; i++) {
        memset(va_arg(valist, unsigned char*), 0, sizeof(va_arg(valist, unsigned char*)));
    }

    va_end(valist);
    return 0;
}