include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(googletest)

include(GoogleTest)

add_executable(crypto_test crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE filecrypt_lib gtest_main OpenSSL::Crypto)
gtest_discover_tests(crypto_test PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")

add_executable(options_test options_test.cpp)
target_link_libraries(options_test PRIVATE filecrypt_lib gtest_main OpenSSL::Crypto)
gtest_discover_tests(options_test)

add_executable(functional_test functional_test.cpp)
target_link_libraries(functional_test PRIVATE filecrypt_lib gtest_main OpenSSL::Crypto)
gtest_discover_tests(functional_test PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
