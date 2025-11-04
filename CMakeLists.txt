cmake_minimum_required(VERSION 3.16)
project(filecrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(SANITIZER_FLAGS "-fsanitize=address,undefined")
    add_compile_options(
        "$<$<CONFIG:Debug>:${SANITIZER_FLAGS}>"
        "$<$<CONFIG:Debug>:-fno-omit-frame-pointer>"
    )
    add_link_options("$<$<CONFIG:Debug>:${SANITIZER_FLAGS}>")
endif()

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(LIB_SOURCES
    src/crypto.cpp
    src/crypto.h
    src/file.cpp
    src/file.h
    src/options.cpp
    src/options.h
    src/result.h
    src/functions.cpp
    src/functions.h
)

add_library(filecrypt_lib ${LIB_SOURCES})
target_include_directories(filecrypt_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(filecrypt_lib PRIVATE OpenSSL::Crypto)

target_compile_options(filecrypt_lib PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
)

add_executable(filecrypt src/main.cpp)
target_link_libraries(filecrypt PRIVATE filecrypt_lib)

enable_testing()

add_subdirectory(tests)
