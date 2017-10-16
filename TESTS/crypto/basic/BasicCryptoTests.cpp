/*
 * nRF52 ubirch Crypto library tests.
 *
 * @author Waldemar Grünwald
 * @date 2017-10-05
 *
 * Copyright 2017 ubirch GmbH (https://ubirch.com)
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

#include "mbed.h"
#include <nacl/armnacl.h>
#include <ubirchCrypto.h>

#include "utest/utest.h"
#include "unity/unity.h"
#include "greentea-client/test_env.h"
#include "../../../ubirch-mbed-nacl-cm0/TESTS/testhelper.h"

using namespace utest::v1;

// randomly generated Keys for testing
const unsigned char testPubKey[crypto_sign_PUBLICKEYBYTES] = {
0x13, 0x25, 0x81, 0x6B, 0x2A, 0x20, 0xF4, 0xC3, 0xC1, 0xC5, 0x26, 0x7D, 0x0D, 0xC6, 0xCF, 0xF5,
0xFC, 0xE4, 0xB8, 0xA0, 0x45, 0x85, 0x3D, 0x62, 0xF8, 0xC7, 0x23, 0x9D, 0xF0, 0x3F, 0x85, 0x2E
};

const unsigned chartestSecKey[crypto_sign_SECRETKEYBYTES] = {
0x88, 0x42, 0x9A, 0xD2, 0x50, 0x44, 0x55, 0x54, 0xD4, 0xC0, 0x9A, 0x9A, 0xA1, 0x6C, 0xC9, 0x92,
0xF3, 0x50, 0xD4, 0x6D, 0xA0, 0x8F, 0x58, 0x8F, 0x41, 0xE8, 0x3E, 0xF2, 0xAF, 0x09, 0xCA, 0xA0,
0x13, 0x25, 0x81, 0x6B, 0x2A, 0x20, 0xF4, 0xC3, 0xC1, 0xC5, 0x26, 0x7D, 0x0D, 0xC6, 0xCF, 0xF5,
0xFC, 0xE4, 0xB8, 0xA0, 0x45, 0x85, 0x3D, 0x62, 0xF8, 0xC7, 0x23, 0x9D, 0xF0, 0x3F, 0x85, 0x2E
};



void TestCryptoImportKey() {
    crypto myCrypto, otherCrypto;

    TEST_ASSERT_TRUE_MESSAGE(myCrypto.importPublicKey(testPubKey), "failed to import key");
    const unsigned char *testKey = myCrypto.getBackendPublicKey();
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPubKey, testKey, crypto_sign_PUBLICKEYBYTES,
                                         "data read does not match written data");
}

void TestCryptoEncodeDecodeMessage() {
    crypto myCrypto;

    // create message and fill it with random bytes
    uint16_t messageLength = 100;
    unsigned char *origMessage = new unsigned char[messageLength];
    for (int i = 0; i < messageLength; i++) {
        origMessage[i] = (unsigned char) (random() & 0xFF);
    }
    // encode the message
    unsigned char *encMessage = myCrypto.encodeMessageBase64(origMessage, messageLength);
    TEST_ASSERT_TRUE_MESSAGE(encMessage != NULL, "failed to encode message");
    // decode the message
    unsigned char *decMessage = myCrypto.decodeMessageBase64(encMessage, strlen((const char *) (encMessage)));
    TEST_ASSERT_TRUE_MESSAGE(decMessage != NULL, "failed to decode message");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(origMessage, decMessage, messageLength,
                                         "data read does not match written data");

    delete origMessage;
}

control_t TestCryptoSigningVerifyingMessage(const size_t repeated) {
    crypto myCrypto, otherCrypto;

    // create message and fill it with random bytes
    uint16_t messageLength = 100;
    unsigned char *origMessage = new unsigned char[messageLength];
    for (int i = 0; i < messageLength; i++) {
        origMessage[i] = (unsigned char) (random() & 0xFF);
    }
    // create keys
    TEST_ASSERT_TRUE_MESSAGE(myCrypto.createKeyPair(), "failed to create first key pair");
    TEST_ASSERT_TRUE_MESSAGE(otherCrypto.createKeyPair(), "failed to create second key pair");

    // import the public Keys from the each other
    const unsigned char *myPubKey = myCrypto.getMyPublicKey();
    TEST_ASSERT_TRUE_MESSAGE(otherCrypto.importPublicKey(myPubKey), "failed to import first public key");
    const unsigned char *otherPubKey = otherCrypto.getMyPublicKey();
    TEST_ASSERT_TRUE_MESSAGE(myCrypto.importPublicKey(otherPubKey), "failed to import second public key");

    // sign the messages
    unsigned char *mySignature = myCrypto.signMessage(origMessage, messageLength);
    TEST_ASSERT_TRUE_MESSAGE(*mySignature != NULL, "failed to sign first message");
    unsigned char *otherSignature = otherCrypto.signMessage(origMessage, messageLength);
    TEST_ASSERT_TRUE_MESSAGE(*otherSignature != NULL, "failed to sign second message");

    // verify the messages
    TEST_ASSERT_TRUE_MESSAGE(myCrypto.verifySignature(otherSignature, origMessage, messageLength),
                             "failed to verify second signature");
    TEST_ASSERT_TRUE_MESSAGE(otherCrypto.verifySignature(mySignature, origMessage, messageLength),
                             "failed to verify first signature");
    delete origMessage;

    return (repeated < 10) ? CaseRepeatAll : CaseNext;
}

utest::v1::status_t greentea_failure_handler(const Case *const source, const failure_t reason) {
    greentea_case_failure_abort_handler(source, reason);
    return STATUS_CONTINUE;
}

Case cases[] = {
Case("Crypto test import backend key-0", TestCryptoImportKey, greentea_failure_handler),
Case("Crypto test encode and decode message base64-0", TestCryptoEncodeDecodeMessage, greentea_failure_handler),
Case("Crypto test sign and verify message-0", TestCryptoSigningVerifyingMessage, greentea_failure_handler),
};

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(150, "default_auto");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}