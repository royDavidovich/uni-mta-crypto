cmake_minimum_required(VERSION 3.30)
project(uni_mta_crypto C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(uni_mta_crypto
    src/cipher_manager.c
        src/encryptor.c
        src/decryptor.c
)

target_link_libraries(uni_mta_crypto mta_rand mta_crypt crypto)
