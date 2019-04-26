//
// Created by zutt on 4/20/19.
//

#ifndef PASSWORDMANAGER_USERINTERACTION_H
#define PASSWORDMANAGER_USERINTERACTION_H

#include <stdio.h>
#endif //PASSWORDMANAGER_USERINTERACTION_H

const int getUserString(char* result);

const int getUserInt();

const int writeUserString(const char* message);

const int writeUserStringThenNumber(const char* message, int number);

const int writeUserStringWithEndline(const char* message);

const int writeUserInt(int number);