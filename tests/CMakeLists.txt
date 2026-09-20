cmake_minimum_required(VERSION 3.28)
project(pico_all_tests LANGUAGES C)
set(CMAKE_C_STANDARD 11)
enable_testing()
add_executable(storage_test storage_test.c
    ../src/app_registry.c
    ../pico-keys-sdk/src/fs/file.c
    ../pico-keys-sdk/src/fs/flash.c
)
target_compile_definitions(storage_test PRIVATE ENABLE_EMULATION)
target_include_directories(storage_test PRIVATE
    ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include
)
target_compile_options(storage_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(storage_test PRIVATE -Wl,--gc-sections)
add_test(NAME storage_and_app_isolation COMMAND storage_test)
set_tests_properties(storage_and_app_isolation PROPERTIES TIMEOUT 15)
