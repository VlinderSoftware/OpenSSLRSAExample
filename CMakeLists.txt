# CMakeList.txt : CMake project for OpenSSLRSAExample, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("OpenSSLRSAExample")

include(FindOpenSSL)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add source to this project's executable.
add_executable (gen "gen.cpp" "config.hpp" "lib.cpp" "lib.hpp")
add_executable (sign "sign.cpp" "config.hpp" "lib.cpp" "lib.hpp")
add_executable (verify "verify.cpp" "config.hpp" "lib.cpp" "lib.hpp")

target_link_libraries(gen OpenSSL::Crypto)
target_link_libraries(sign OpenSSL::Crypto)
target_link_libraries(verify OpenSSL::Crypto)
# TODO: Add tests and install targets if needed.
