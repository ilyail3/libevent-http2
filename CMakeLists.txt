cmake_minimum_required(VERSION 3.5)
project(libevent)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp)
link_libraries(event event_openssl ssl crypto nghttp2)

add_executable(libevent ${SOURCE_FILES})