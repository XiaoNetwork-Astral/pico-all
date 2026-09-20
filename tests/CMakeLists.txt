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

add_executable(led_test led_test.c)
target_compile_definitions(led_test PRIVATE ENABLE_EMULATION)
target_include_directories(led_test PRIVATE
    ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include
)
target_compile_options(led_test PRIVATE -UNDEBUG)
add_test(NAME led_state_and_timing COMMAND led_test)
set_tests_properties(led_state_and_timing PROPERTIES TIMEOUT 15)

add_executable(apdu_transport_test apdu_transport_test.c ../pico-keys-sdk/src/apdu.c)
target_compile_definitions(apdu_transport_test PRIVATE USB_ITF_HID USB_ITF_CCID)
target_include_directories(apdu_transport_test PRIVATE
    ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/usb
    ../pico-keys-sdk/third-party/mbedtls/include
)
target_compile_options(apdu_transport_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(apdu_transport_test PRIVATE -Wl,--gc-sections)
add_test(NAME apdu_transport_routing COMMAND apdu_transport_test)
set_tests_properties(apdu_transport_routing PROPERTIES TIMEOUT 15)

add_executable(piv_reset_test piv_reset_test.c
    ../src/piv/cmd_reset.c ../src/openpgp/cmd_terminate_df.c ../src/openpgp/key_container.c)
target_compile_definitions(piv_reset_test PRIVATE ENABLE_EMULATION)
target_include_directories(piv_reset_test PRIVATE
    ../src/piv ../src/openpgp ../pico-keys-sdk/src ../pico-keys-sdk/src/fs
    ../pico-keys-sdk/src/rng ../pico-keys-sdk/src/usb ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include
)
target_compile_options(piv_reset_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(piv_reset_test PRIVATE -Wl,--gc-sections)
add_test(NAME piv_openpgp_reset_isolation COMMAND piv_reset_test)
set_tests_properties(piv_openpgp_reset_isolation PROPERTIES TIMEOUT 15)
