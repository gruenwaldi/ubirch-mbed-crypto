/*
 * Testing the key exchange protocol.
 *
 * @author Matthias L. Jugel
 * @date 2017-10-15
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

#include <unity/unity.h>
#include <Base64.h>
#include <KeyPair.h>

#include "utest/utest.h"
#include "greentea-client/test_env.h"
#include "../../../ubirch-mbed-nacl-cm0/TESTS/testhelper.h"

using namespace utest::v1;

static const int messageLength = crypto_sign_PUBLICKEYBYTES + 4;
static const size_t signedMessageLength = messageLength + crypto_sign_BYTES;

// we need to read the server side data in slices, as sending too many characters fails
void greentea_parse_kv_slice(char *k, char *v, const int keySize, const unsigned int valueSize,
                             const unsigned int sliceSize) {
    memset(v, 0, sizeof(v));
    int idx = 0, len = 0;
    do {
        greentea_parse_kv(k, v+idx, keySize, sliceSize + 1);
        len = strlen(v+idx);
        idx += len;
    } while (len == sliceSize && idx < valueSize);
    printf("[%d] %s\r\n", (int) strlen(v), v);
}

void TestCryptoKeyExchange() {
    char k[48], v[255];
    ED25519KeyPair deviceKey, serverKey;
    Base64 base64;
    size_t b64Length;
    char *encodedMessage;
    unsigned char deviceSignedDeviceMessage[signedMessageLength];
    unsigned char deviceNone[4];

    memset(deviceSignedDeviceMessage, 0, signedMessageLength);
    memset(deviceNone, 0, 4);

    // generate the device key
    deviceKey.generate();

    // STEP 1 - send device message (Dpub, Dnonce) signed by device to server
    printf("STEP 1 (D->S)\r\n");
    randombytes(deviceNone, 4);
    memcpy(deviceSignedDeviceMessage, deviceKey.getPublicKey()->key, crypto_sign_PUBLICKEYBYTES);
    memcpy(deviceSignedDeviceMessage + crypto_sign_PUBLICKEYBYTES, deviceNone, 4);
    // prepare complete signed device message, including the signature
    ED25519Signature *deviceMessageSignature = deviceKey.sign(deviceSignedDeviceMessage, messageLength);
    memcpy(deviceSignedDeviceMessage + messageLength, deviceMessageSignature, crypto_sign_BYTES);
    delete deviceMessageSignature;
    // encode message in base64 and send to server
    encodedMessage = base64.Encode((const char *) deviceSignedDeviceMessage, signedMessageLength, &b64Length);
    greentea_send_kv("deviceSignedDeviceMessage", encodedMessage);
    free(encodedMessage);

    // STEP 2 - receive server message (Spub, Snonce) signed by the server
    printf("STEP 2 (S->D)\r\n");
    greentea_parse_kv_slice(k, v, sizeof(k), sizeof(v), 30);
    TEST_ASSERT_EQUAL_STRING("serverSignedServerMessage", k);
    char *serverSignedServerMessage = base64.Decode(v, strlen(v), &b64Length);
    serverKey.importPublicKey(reinterpret_cast<const unsigned char *>(serverSignedServerMessage),
                              crypto_sign_PUBLICKEYBYTES);

    TEST_ASSERT_EQUAL_INT_MESSAGE(signedMessageLength, b64Length, "server message length mismatch");
    bool serverSignedServerMessageVerification = serverKey.verify(
            (const unsigned char *) serverSignedServerMessage, messageLength,
            (ED25519Signature *) (serverSignedServerMessage + messageLength));
    TEST_ASSERT_TRUE_MESSAGE(serverSignedServerMessageVerification, "message verification failed");

    // STEP 3 - receive device message (Dpub, Dnonce) signed by server from server
    printf("STEP 3 (S->D)\r\n");
    greentea_parse_kv_slice(k, v, sizeof(k), sizeof(v), 30);
    TEST_ASSERT_EQUAL_STRING("serverSignedDeviceMessage", k);
    char *serverSignedDeviceMessage = base64.Decode(v, strlen(v), &b64Length);
    TEST_ASSERT_EQUAL_INT_MESSAGE(signedMessageLength, b64Length, "server message length mismatch");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(deviceSignedDeviceMessage, serverSignedDeviceMessage, messageLength,
                                         "message changed");
    bool serverSignedDeviceMessageVerification = serverKey.verify(
            (const unsigned char *) serverSignedDeviceMessage, messageLength,
            (ED25519Signature *) (serverSignedDeviceMessage + messageLength));
    TEST_ASSERT_TRUE_MESSAGE(serverSignedDeviceMessageVerification, "message verification failed");
    free(serverSignedDeviceMessage);

    // STEP 4 - send server message (Spub, Snonce) signed by device to server
    printf("STEP 4 (D->S)\r\n");
    unsigned char *deviceSignedServerMessage = (unsigned char *) serverSignedServerMessage;
    ED25519Signature *serverMessageSignature = deviceKey.sign(deviceSignedServerMessage, messageLength);
    memcpy(deviceSignedServerMessage + messageLength, serverMessageSignature, crypto_sign_BYTES);
    delete serverMessageSignature;
    // encode message in base64 and send to server
    encodedMessage = base64.Encode((const char *) deviceSignedServerMessage, signedMessageLength, &b64Length);
    greentea_send_kv("deviceSignedServerMessage", encodedMessage);
    free(encodedMessage);
    free(serverSignedServerMessage);

    greentea_parse_kv(k, v, sizeof(k), sizeof(v));
    TEST_ASSERT_EQUAL_STRING("serverVerification", k);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("SUCCESS", v, "key exchange final step failed");
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(600, "KeyExchangeTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("Crypto test key exchange", TestCryptoKeyExchange, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}