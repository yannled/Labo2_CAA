//
// Created by zutt on 4/21/19.
//

#include <malloc.h>
#include "FileManager.h"

int remove_charEndLine(unsigned char *dest) {
    int removed = 0;
    char *tmp;

    while (*dest) {
        tmp = strchr(dest, '\n');
        if (NULL == tmp) {
            break;
        } else {
            size_t len = strlen(tmp + 1);
            memmove(tmp, tmp + 1, len);
            tmp[len] = 0;
            ++removed;
            dest = tmp;
        }
    }
    return removed;
}


int writeKeyValueInFile(char *key, unsigned char *value, unsigned long long valueSize) {
    unsigned char* base64Value;
    base64Value = base64_encode(value,valueSize, NULL);
    remove_charEndLine(base64Value);
    FILE *f = fopen("password.txt", "a");
    if (f == NULL) {
        freopen("password.txt", "a", f);
    } else {
        fprintf(f, "%s:%s\n", key, base64Value);
        fclose(f);
        free(base64Value);
        return 0;
    }
}

int readKeyValueFromFile(char *key, unsigned char *out) {
    FILE *f = fopen("password.txt", "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char delim[] = ":";
    if (f == NULL) {
        return -1;
    } else {
        while ((read = getline(&line, &len, f)) != -1) {
            if (0 == compareString(line, key)) {
                unsigned char *ptr = strtok(line, delim);
                ptr = strtok(NULL, delim);

                size_t length;
                unsigned char *temp;
                temp = base64_decode(ptr, strlen(ptr), &length);
                strcpy(out, temp);
                free(temp);
                break;
            }
        }

        fclose(f);
        if (line)
            free(line);
    }
}

int deleteKeyValueInFile(char *key) {
    FILE *initFile = fopen("password.txt", "r");
    FILE *tempFile = fopen("TempPassword.txt", "a");

    //Copy initFile in tempFile without the key specified
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    if (initFile == NULL) {
        return -1;
    }

    if (tempFile == NULL) {
        freopen("TempPassword.txt", "a", tempFile);
    }
    while ((read = getline(&line, &len, initFile)) != -1) {
        if (0 != compareString(line, key)) {
            fprintf(tempFile, "%s", line);
        }
    }
    fclose(initFile);
    fclose(tempFile);

    //Delete initFile
    int status = remove("password.txt");

    if (status != 0){
        printf("Unable to delete the file\n");
        perror("Following error occurred");
    }

    //rename tempFile to initfile name.
    status = rename("TempPassword.txt", "password.txt");

    if(status != 0) {
        printf("Error: unable to rename the file");
    }
}

int compareString(char *line, char *wordsToSearch) {
    int i = 0;
    int j = 0;

    for (i; i < strlen(line); i++) {
        if (line[i] == wordsToSearch[j]) {
            j++;
        }
    }

    if (strlen(wordsToSearch) == j)
        return 0;
    else
        return -1;
}

