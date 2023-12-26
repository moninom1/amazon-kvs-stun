cmake_minimum_required(VERSION 3.10)
project(stunPoc)

# Set the source files and include directories
set(SOURCE_FILES
    source/test.c
    source/stun.c
    source/crc32.c
    source/endianness.c
    source/hmac.c
    source/common/stun_e.c
)

# Set the header files
set(HEADER_FILES
    source/include/stun.h
    source/include/Include_i.h
    source/include/commondefs.h
    source/include/crc32.h
    source/include/hmac.h
    source/common/include/stun_e.h
)

# Create an executable
add_executable(stun_test ${SOURCE_FILES} ${HEADER_FILES})

target_include_directories(stun_test PRIVATE source/include source/common/include)
