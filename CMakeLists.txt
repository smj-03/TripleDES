cmake_minimum_required(VERSION 3.29)
project(3DES C)

set(CMAKE_C_STANDARD 23)

add_executable(
        3DES
        params.c
        des.h
        des.c
        main.c
)
