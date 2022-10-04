cmake_minimum_required(VERSION 3.10.2)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_BUILD_TYPE)
set(PROJECT_NAME htserv)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

file(GLOB SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/../frozen/frozen.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
file(GLOB HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

project(${PROJECT_NAME} LANGUAGES C)
add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES})

include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../libmicrohttpd/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../frozen
)

target_link_libraries(${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/../libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a
	-lpthread -lgnutls)
