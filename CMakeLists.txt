cmake_minimum_required(VERSION 3.5)
project(libevent)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#file(GLOB SOURCE_FILES RELATIVE "source" "source/*.h" "source/*.cpp")
set(SOURCE_FILES source/http2_server.h source/ssl_config.cpp source/ssl_config.h source/unused.h source/main.cpp source/http2_session_data.h source/http2_streams.h source/http2_streams.cpp source/http2_sessions.cpp source/http2_sessions.h source/http2_stream.h)

link_libraries(event event_openssl ssl crypto nghttp2)

add_executable(libevent ${SOURCE_FILES})