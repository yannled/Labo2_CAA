//
// Created by zutt on 4/22/19.
//

#ifndef PASSWORDMANAGER_BASE64_H
#define PASSWORDMANAGER_BASE64_H

#include <glob.h>
#include <zconf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#endif //PASSWORDMANAGER_BASE64_H

unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len);

unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len);