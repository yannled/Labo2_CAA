//
// Created by zutt on 4/20/19.
//

#include "UserInteraction.h"

const int getUserString(char* result){
    scanf("%s",result);
    return 0;
}

const int getUserInt(){
    int result = 0;
    scanf("%d",&result);
    return result;
}

const int writeUserString(const char* message){
    printf("%s", message);
    return 0;
}

const int writeUserStringWithEndline(const char* message){
    printf("%s\n", message);
    return 0;
}

const int writeUserStringThenNumber(const char* message, int number){
    printf("%s %d\n", message, number);
    return 0;
}

const int writeUserInt(int number){
    printf("%d", number);
    return 0;
}