cmake_minimum_required(VERSION 3.13)
project(passwordManager C)

set(CMAKE_C_STANDARD 11)

add_executable(passwordManager main.c UserInteraction.c UserInteraction.h Crypto.c Crypto.h FileManager.c FileManager.h base64.c base64.h Strings_en.h)