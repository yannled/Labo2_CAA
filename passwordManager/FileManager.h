//
// Created by zutt on 4/21/19.
//

#ifndef PASSWORDMANAGER_FILEMANAGER_H
#define PASSWORDMANAGER_FILEMANAGER_H
#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "base64.h"
#endif //PASSWORDMANAGER_FILEMANAGER_H

int writeKeyValueInFile(char* key, unsigned char* value, unsigned long long valueSize);

int readKeyValueFromFile(char* key, unsigned char* out);

int deleteKeyValueInFile(char* key);

//https://stackoverflow.com/questions/27090069/check-if-a-string-of-type-char-contains-another-string
int compareString(char* line, char* wordsToSearch);