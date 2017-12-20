/*
 * ...
 *
 * @author Matthias L. Jugel
 * @date 2017-10-17
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
#include <KeyPair.h>
#include <Base64.h>

#include "utest/utest.h"
#include "unity/unity.h"
#include "greentea-client/test_env.h"
#include "../../../ubirch-mbed-nacl-cm0/TESTS/testhelper.h"

using namespace utest::v1;

// we need to read the server side data in slices, as sending too many characters fails
void greentea_parse_kv_slice(char *k, char *v, const int keySize, const unsigned int valueSize,
                             const unsigned int sliceSize) {
    memset(v, 0, sizeof(v));
    unsigned int idx = 0, len = 0;
    do {
        greentea_parse_kv(k, v+idx, keySize, sliceSize + 1);
        len = strlen(v+idx);
        idx += len;
    } while (len == sliceSize && idx < valueSize);
    printf("[%d] %s\r\n", (int) strlen(v), v);
}

// randomly generated Keys for testing
const ED25519PublicKey testPublicKey = {
        .key = {
                0x13, 0x25, 0x81, 0x6B, 0x2A, 0x20, 0xF4, 0xC3, 0xC1, 0xC5, 0x26, 0x7D, 0x0D, 0xC6, 0xCF, 0xF5,
                0xFC, 0xE4, 0xB8, 0xA0, 0x45, 0x85, 0x3D, 0x62, 0xF8, 0xC7, 0x23, 0x9D, 0xF0, 0x3F, 0x85, 0x2E
        }
};

const ED25519PrivateKey testPrivateKey = {
        .key = {
                0x88, 0x42, 0x9A, 0xD2, 0x50, 0x44, 0x55, 0x54, 0xD4, 0xC0, 0x9A, 0x9A, 0xA1, 0x6C, 0xC9, 0x92,
                0xF3, 0x50, 0xD4, 0x6D, 0xA0, 0x8F, 0x58, 0x8F, 0x41, 0xE8, 0x3E, 0xF2, 0xAF, 0x09, 0xCA, 0xA0,
                0x13, 0x25, 0x81, 0x6B, 0x2A, 0x20, 0xF4, 0xC3, 0xC1, 0xC5, 0x26, 0x7D, 0x0D, 0xC6, 0xCF, 0xF5,
                0xFC, 0xE4, 0xB8, 0xA0, 0x45, 0x85, 0x3D, 0x62, 0xF8, 0xC7, 0x23, 0x9D, 0xF0, 0x3F, 0x85, 0x2E
        }
};

class TestKeyPair : public ED25519KeyPair {
public:
    ED25519PrivateKey *getPrivateKey() { return privateKey; }

    ED25519PublicKey *getPublicKey() { return publicKey; }
};

void TestGenerateKeyPair() {
    TestKeyPair testKeyPair;
    testKeyPair.generate();

    ED25519PrivateKey &privateKey = *testKeyPair.getPrivateKey();
    ED25519PublicKey &publicKey = *testKeyPair.getPublicKey();

    unsigned int nullBytes;
    for (nullBytes = 0; nullBytes < sizeof(ED25519PublicKey) && publicKey.key[nullBytes] == 0; nullBytes++);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(crypto_sign_PUBLICKEYBYTES, nullBytes, "public key generation failed")
    for (nullBytes = 0; nullBytes < sizeof(ED25519PrivateKey) && privateKey.key[nullBytes] == 0; nullBytes++);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(crypto_sign_SECRETKEYBYTES, nullBytes, "private key generation failed");

    // the public key is part of the private key, check that the public key matches that part
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(publicKey.key, privateKey.key +
                                                        (crypto_sign_SECRETKEYBYTES -
                                                         crypto_sign_PUBLICKEYBYTES),
                                         crypto_sign_PUBLICKEYBYTES, "public key does not match");
}

control_t TestSignAndVerifySelf(const size_t n) {
    TestKeyPair testKeyPair;
    testKeyPair.generate();

    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    ED25519Signature *signature = testKeyPair.sign(reinterpret_cast<const unsigned char *>(plaintext), strlen(plaintext));
    TEST_ASSERT_NOT_NULL(signature);

    bool verified = testKeyPair.verify(reinterpret_cast<const unsigned char *>(plaintext), strlen(plaintext), signature);
    TEST_ASSERT_TRUE_MESSAGE(verified, "message verification failed");

    delete signature;

    return (n < 5) ? CaseRepeatAll : CaseNext;
}

void TestImportKeyPair() {
    TestKeyPair testKeyPair;
    testKeyPair.import(testPublicKey, testPrivateKey);

    ED25519PublicKey &importedPublicKey = *testKeyPair.getPublicKey();
    ED25519PrivateKey &importedPrivateKey = *testKeyPair.getPrivateKey();
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPublicKey.key, importedPublicKey.key,
                                         crypto_sign_PUBLICKEYBYTES, "imported public key does not match original");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPrivateKey.key, importedPrivateKey.key,
                                         crypto_sign_SECRETKEYBYTES, "imported private key does not match original");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(&testPublicKey.key, &importedPublicKey.key,
                                  "public key import failed, address match");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(&testPrivateKey.key, &importedPrivateKey.key,
                                  "private key import failed, address match");
}

void TestImportKeyPairFromArrays() {
    TestKeyPair testKeyPair;
    testKeyPair.import(testPublicKey.key, crypto_sign_PUBLICKEYBYTES,
                       testPrivateKey.key, crypto_sign_SECRETKEYBYTES);

    ED25519PublicKey &importedPublicKey = *testKeyPair.getPublicKey();
    ED25519PrivateKey &importedPrivateKey = *testKeyPair.getPrivateKey();
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPublicKey.key, importedPublicKey.key,
                                         crypto_sign_PUBLICKEYBYTES, "imported public key does not match original");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPrivateKey.key, importedPrivateKey.key,
                                         crypto_sign_SECRETKEYBYTES, "imported private key does not match original");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(&testPublicKey.key, &importedPublicKey.key,
                                  "public key import failed, address match");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(&testPrivateKey.key, &importedPrivateKey.key,
                                  "private key import failed, address match");
}


void TestImportPublicKeyFromArray() {
    TestKeyPair testKeyPair;
    testKeyPair.importPublicKey(testPublicKey.key, crypto_sign_PUBLICKEYBYTES);

    ED25519PublicKey &importedPublicKey = *testKeyPair.getPublicKey();
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPublicKey.key, importedPublicKey.key,
                                         crypto_sign_PUBLICKEYBYTES, "imported public key does not match original");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(&testPublicKey.key, &importedPublicKey.key,
                                  "public key import failed, address match");
}


void TestLinkKeyPair() {
    TestKeyPair testKeyPair;
    testKeyPair.link(&testPublicKey, &testPrivateKey);

    ED25519PublicKey &importedPublicKey = *testKeyPair.getPublicKey();
    ED25519PrivateKey &importedPrivateKey = *testKeyPair.getPrivateKey();
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPublicKey.key, importedPublicKey.key,
                                         crypto_sign_PUBLICKEYBYTES, "imported public key does not match original");
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPrivateKey.key, importedPrivateKey.key,
                                         crypto_sign_SECRETKEYBYTES, "imported private key does not match original");
    TEST_ASSERT_EQUAL_PTR_MESSAGE(&testPublicKey.key, &importedPublicKey.key,
                                  "set public key failed, address mismatch");
    TEST_ASSERT_EQUAL_PTR_MESSAGE(&testPrivateKey.key, &importedPrivateKey.key,
                                  "set private key failed, address mismatch");
}

control_t TestSignMessageStaticKey(const size_t repeated) {
    char k[20], v[20];
    Base64 base64;
    size_t b64Length;
    TestKeyPair testKeyPair;
    testKeyPair.link(&testPublicKey, &testPrivateKey);

    char *encodedPublicKey = base64.Encode(reinterpret_cast<const char *>(testPublicKey.key),
                                           sizeof(testPublicKey.key), &b64Length);
    greentea_send_kv("importPublicKey", encodedPublicKey);
    delete[] encodedPublicKey;

    size_t len = random();
    greentea_send_kv("expectedMessageLength", static_cast<const int>(len));

    char *message = new char[len + crypto_sign_BYTES];
    randombytes((unsigned char *) message, len);
    ED25519Signature *signature = testKeyPair.sign(reinterpret_cast<const unsigned char *>(message), len);
    memcpy((void *) (message + len), signature->signature, crypto_sign_BYTES);
    delete signature;

    char *encodedMessage = base64.Encode(message, len + crypto_sign_BYTES, &b64Length);
    delete message;

    greentea_send_kv("verifySignature", encodedMessage);
    delete[] encodedMessage;

    greentea_parse_kv(k, v, sizeof(k), sizeof(v));
    TEST_ASSERT_EQUAL_STRING("verify", k);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("OK", v, "signature verification failed");

    return (repeated < 5) ? CaseRepeatAll : CaseNext;
}


control_t TestVerifyMessageStaticKey(const size_t repeated) {
    char k[20], v[255];
    Base64 base64;
    size_t b64Length;
    TestKeyPair testKeyPair;
    testKeyPair.link(&testPublicKey, &testPrivateKey);

    size_t len = random();
    char *message = new char[len];
    randombytes((unsigned char *) message, len);

    char *encodedMessage = base64.Encode(message, len, &b64Length);
    greentea_send_kv("signMessage", encodedMessage);
    delete[] encodedMessage;

    greentea_parse_kv_slice(k, v, sizeof(k), sizeof(v), 20);
    TEST_ASSERT_EQUAL_STRING("signature", k);

    char *signature = base64.Decode(v, strlen(v), &b64Length);
    printbytes("SIG ", signature, ((int) b64Length));
    printf("\r\n");

    TEST_ASSERT_EQUAL_INT_MESSAGE(64, b64Length, "signature length mismatch");
    testKeyPair.verify(reinterpret_cast<const unsigned char *>(message), len, (ED25519Signature *) signature);

    delete[] signature;

    return (repeated < 5) ? CaseRepeatAll : CaseNext;
}

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(150, "KeyPairTests");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("Crypto test generate keypair", TestGenerateKeyPair, greentea_case_failure_abort_handler),
            Case("Crypto test import keypair", TestImportKeyPair, greentea_case_failure_abort_handler),
            Case("Crypto test import keypair from arrays", TestImportKeyPairFromArrays, greentea_case_failure_abort_handler),
            Case("Crypto test import public key from array", TestImportPublicKeyFromArray, greentea_case_failure_abort_handler),
            Case("Crypto test set keypair", TestLinkKeyPair, greentea_case_failure_abort_handler),
            Case("Crypto test sign message", TestSignMessageStaticKey, greentea_case_failure_abort_handler),
            Case("Crypto test verify message", TestVerifyMessageStaticKey, greentea_case_failure_abort_handler),
            Case("Crypto test sign/verify self", TestSignAndVerifySelf, greentea_case_failure_abort_handler),
    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}