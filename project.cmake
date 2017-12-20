add_executable(tests-crypto-base64 TESTS/crypto/base64/Base64Tests.cpp)
target_link_libraries(tests-crypto-base64 ubirch-mbed-crypto)
add_executable(tests-crypto-keys TESTS/crypto/keys/KeyHandlingTests.cpp)
target_link_libraries(tests-crypto-keys ubirch-mbed-crypto)
add_executable(tests-crypto-protocol TESTS/crypto/protocol/KeyExchangeTests.cpp)
target_link_libraries(tests-crypto-protocol ubirch-mbed-crypto)

ADD_CUSTOM_TARGET(mbed-cli-test
        COMMAND ${CMAKE_COMMAND} -E echo "mbed test -n tests-* --build BUILD/${CMAKE_BUILD_TYPE} --profile ${MBED_BUILD_PROFILE}"
        COMMAND mbed test -v -n tests-crypto-* --profile ${MBED_BUILD_PROFILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )