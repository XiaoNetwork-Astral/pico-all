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

# Use the same vendored crypto implementation, without hardware acceleration.
set(u2f_crypto_sources
    aes aesni padlock platform asn1parse asn1write bignum bignum_core ccm cmac
    cipher cipher_wrap constant_time ecdsa ecdh ecp ecp_curves gcm hkdf md md5
    oid pkcs5 platform_util rsa rsa_alt_helpers sha1 sha256 sha512 chachapoly
    chacha20 poly1305 ripemd160 des x509write x509write_crt x509_create
    x509write_csr base64 pem pk pk_wrap pkwrite x509 x509_crt pkparse pk_ecc
    pkcs12 eddsa sha3)
list(TRANSFORM u2f_crypto_sources PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/../pico-keys-sdk/third-party/mbedtls/library/")
list(TRANSFORM u2f_crypto_sources APPEND ".c")
add_library(u2f_test_crypto STATIC ${u2f_crypto_sources})
target_include_directories(u2f_test_crypto PUBLIC ../pico-keys-sdk/third-party/mbedtls/include)
target_compile_definitions(u2f_test_crypto PUBLIC
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../pico-keys-sdk/config/mbedtls_config.h"
    MBEDTLS_EDDSA_C=1 MBEDTLS_ECP_DP_ED25519_ENABLED=1
    MBEDTLS_ECP_DP_ED448_ENABLED=1 MBEDTLS_SHA3_C=1)
target_compile_options(u2f_test_crypto PRIVATE -ffunction-sections -fdata-sections)
add_executable(u2f_keys_test u2f_keys_test.c ../src/fido/u2f_keys.c
    ../src/fido/key_derivation.c ../src/fido/certificate.c ../src/fido/cbor_reset.c
    ../src/fido/cmd_register.c ../src/fido/cmd_authenticate.c)
target_link_libraries(u2f_keys_test PRIVATE u2f_test_crypto)
target_compile_definitions(u2f_keys_test PRIVATE ENABLE_EMULATION)
target_include_directories(u2f_keys_test PRIVATE
    ../src/fido ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/rng
    ../pico-keys-sdk/src/usb ../pico-keys-sdk/src/usb/emulation ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/tinycbor/src)
target_compile_options(u2f_keys_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(u2f_keys_test PRIVATE -Wl,--gc-sections)
add_test(NAME u2f_keys_and_commands COMMAND u2f_keys_test)
set_tests_properties(u2f_keys_and_commands PROPERTIES TIMEOUT 30)

add_executable(otp_root_test otp_root_test.c ../pico-keys-sdk/src/otp/otp_root.c)
target_include_directories(otp_root_test PRIVATE ../pico-keys-sdk/src/otp)
target_link_libraries(otp_root_test PRIVATE u2f_test_crypto)
target_compile_options(otp_root_test PRIVATE -UNDEBUG)
add_test(NAME otp_root_power_cut_model COMMAND otp_root_test)
set_tests_properties(otp_root_power_cut_model PROPERTIES TIMEOUT 15)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME firmware_cli_and_signing
        COMMAND ${Python3_EXECUTABLE} -m unittest discover -s tests -p "firmware_*_test.py")
    set_tests_properties(firmware_cli_and_signing PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 30)
    add_test(NAME security_management_protocol
        COMMAND ${Python3_EXECUTABLE} -m unittest discover -s tests -p security_protocol_test.py)
    set_tests_properties(security_management_protocol PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
        ENVIRONMENT "OTP_SIM_COMMAND=[\"$<TARGET_FILE:otp_root_test>\"]"
        TIMEOUT 120)
endif()

add_executable(usb_reboot_test usb_reboot_test.c)
target_compile_definitions(usb_reboot_test PRIVATE ENABLE_EMULATION USB_ITF_CCID PICOKEYS_USB_REBOOT_TEST)
target_include_directories(usb_reboot_test PRIVATE
    ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/usb
    ../pico-keys-sdk/src/usb/emulation ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include)
target_compile_options(usb_reboot_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(usb_reboot_test PRIVATE -Wl,--gc-sections)
find_package(Threads REQUIRED)
target_link_libraries(usb_reboot_test PRIVATE Threads::Threads)
add_test(NAME usb_bootsel_event_delivery COMMAND usb_reboot_test)
set_tests_properties(usb_bootsel_event_delivery PROPERTIES TIMEOUT 15)

set(attestation_cbor_sources cborparser cborencoder cborencoder_close_container_checked
    cborparser_dup_string cborerrorstrings)
list(TRANSFORM attestation_cbor_sources PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/../pico-keys-sdk/third-party/tinycbor/src/")
list(TRANSFORM attestation_cbor_sources APPEND ".c")
add_executable(org_attestation_test org_attestation_test.c ../src/fido/cbor.c
    ../src/fido/cbor_reset.c ${attestation_cbor_sources})
target_link_libraries(org_attestation_test PRIVATE u2f_test_crypto)
target_compile_definitions(org_attestation_test PRIVATE ENABLE_EMULATION)
target_include_directories(org_attestation_test PRIVATE
    ../src/fido ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/rng
    ../pico-keys-sdk/src/usb ../pico-keys-sdk/src/usb/emulation ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/tinycbor/src)
target_compile_options(org_attestation_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(org_attestation_test PRIVATE -Wl,--gc-sections)
if(Python3_Interpreter_FOUND)
    add_test(NAME org_attestation_protocol
        COMMAND ${Python3_EXECUTABLE} -m unittest discover -s tests -p org_attestation_test.py)
    set_tests_properties(org_attestation_protocol PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
        ENVIRONMENT "ATTESTATION_TEST_COMMAND=[\"$<TARGET_FILE:org_attestation_test>\"]"
        TIMEOUT 90)
endif()

add_executable(piv_rsa4096_test piv_rsa4096_test.c ../src/openpgp/piv.c
    ../src/piv/cmd_asym_keygen.c ../src/piv/cmd_attestation.c
    ../src/piv/cmd_put_data.c ../pico-keys-sdk/src/tlv.c)
target_link_libraries(piv_rsa4096_test PRIVATE u2f_test_crypto)
target_compile_definitions(piv_rsa4096_test PRIVATE ENABLE_EMULATION)
target_include_directories(piv_rsa4096_test PRIVATE
    ../src/openpgp ../src/piv ../pico-keys-sdk/src ../pico-keys-sdk/src/fs
    ../pico-keys-sdk/src/rng ../pico-keys-sdk/src/usb ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/libcvc/include ../pico-keys-sdk/third-party/libcvc/src)
# Discard the unused app-registration callback along with its unrelated commands.
set_property(TARGET piv_rsa4096_test PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
target_compile_options(piv_rsa4096_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(piv_rsa4096_test PRIVATE -Wl,--gc-sections)
add_test(NAME piv_rsa4096_and_attestation COMMAND piv_rsa4096_test)
set_tests_properties(piv_rsa4096_and_attestation PROPERTIES TIMEOUT 90)

add_executable(hid_busy_test hid_busy_test.c)
target_compile_definitions(hid_busy_test PRIVATE ENABLE_EMULATION USB_ITF_HID)
target_include_directories(hid_busy_test PRIVATE
    ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/usb
    ../pico-keys-sdk/src/usb/emulation ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include)
target_compile_options(hid_busy_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(hid_busy_test PRIVATE -Wl,--gc-sections)
add_test(NAME hid_busy_request_isolation COMMAND hid_busy_test)
set_tests_properties(hid_busy_request_isolation PROPERTIES TIMEOUT 15)

add_executable(phy_led_test phy_led_test.c)
target_compile_definitions(phy_led_test PRIVATE ENABLE_EMULATION)
target_include_directories(phy_led_test PRIVATE
    ../pico-keys-sdk/src/otp
    ../pico-keys-sdk/src ../pico-keys-sdk/src/fs ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include)
target_compile_options(phy_led_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(phy_led_test PRIVATE -Wl,--gc-sections)
add_test(NAME phy_status_light_roundtrip COMMAND phy_led_test)


add_executable(hsm_pin_metadata_test hsm_pin_metadata_test.c ../src/hsm/cmd_verify.c)
target_compile_definitions(hsm_pin_metadata_test PRIVATE ENABLE_EMULATION)
target_include_directories(hsm_pin_metadata_test PRIVATE
    ../src/hsm ../pico-keys-sdk/src ../pico-keys-sdk/src/fs
    ../pico-keys-sdk/src/usb ../pico-keys-sdk/src/usb/emulation ../pico-keys-sdk/src/compat
    ../pico-keys-sdk/third-party/mbedtls/include)
target_compile_options(hsm_pin_metadata_test PRIVATE -ffunction-sections -fdata-sections -UNDEBUG)
target_link_options(hsm_pin_metadata_test PRIVATE -Wl,--gc-sections)
add_test(NAME hsm_read_only_pin_metadata COMMAND hsm_pin_metadata_test)
