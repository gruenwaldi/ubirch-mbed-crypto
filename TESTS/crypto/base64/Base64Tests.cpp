/*
 * Tests for the Base64 implementation.
 *
 * Tests adapted from MIT licensed BouncyCastle tests as well as RFC 4648 test vectors.
 *
 * @author Matthias L. Jugel
 * @date 2017-10-18
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
#include <Base64.h>

#include "utest/utest.h"
#include "unity/unity.h"
#include "greentea-client/test_env.h"
#include "../../../ubirch-mbed-nacl-cm0/TESTS/testhelper.h"

using namespace utest::v1;

void TestBase64RFC4648() {
    Base64 base64;

    size_t o;
    TEST_ASSERT_EQUAL_STRING("", base64.Encode("", 0, &o));
    TEST_ASSERT_EQUAL_INT(0, o);
    TEST_ASSERT_EQUAL_STRING("Zg==", base64.Encode("f", 1, &o));
    TEST_ASSERT_EQUAL_INT(4, o);
    TEST_ASSERT_EQUAL_STRING("Zm8=", base64.Encode("fo", 2, &o));
    TEST_ASSERT_EQUAL_INT(4, o);
    TEST_ASSERT_EQUAL_STRING("Zm9v", base64.Encode("foo", 3, &o));
    TEST_ASSERT_EQUAL_INT(4, o);
    TEST_ASSERT_EQUAL_STRING("Zm9vYg==", base64.Encode("foob", 4, &o));
    TEST_ASSERT_EQUAL_INT(8, o);
    TEST_ASSERT_EQUAL_STRING("Zm9vYmE=", base64.Encode("fooba", 5, &o));
    TEST_ASSERT_EQUAL_INT(8, o);
    TEST_ASSERT_EQUAL_STRING("Zm9vYmFy", base64.Encode("foobar", 6, &o));
    TEST_ASSERT_EQUAL_INT(8, o);
}


control_t TestBase64PowerOfTwo(const size_t n) {
    Base64 base64;

    unsigned int size = static_cast<unsigned int>(1024 << (n-1));
    printf("BASE64: %u bytes\r\n", size);

    unsigned char *orig = new unsigned char[size];
    randombytes(orig, size);
    printbytes("I", orig, size); printf("\r\n");

    size_t encodedLength, decodedLength;
    char *encoded = base64.Encode(reinterpret_cast<const char *>(orig), size, &encodedLength);
    char *decoded = base64.Decode(encoded, encodedLength, &decodedLength);
    printbytes("O", decoded, decodedLength); printf("\r\n");

    TEST_ASSERT_EQUAL_INT(size, decodedLength);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(orig, decoded, size);

    delete[] orig;
    delete[] encoded;
    delete[] decoded;

    return (n < 4) ? CaseRepeatAll : CaseNext;
}

control_t TestBase64PowerOfTwoPlusOne(const size_t n) {
    Base64 base64;

    unsigned int size = static_cast<unsigned int>((1024 << (n-1))+1);
    printf("BASE64: %d bytes\r\n", size);

    unsigned char *orig = new unsigned char[size];
    randombytes(orig, size);
    printbytes("I", orig, size); printf("\r\n");

    size_t encodedLength, decodedLength;
    char *encoded = base64.Encode(reinterpret_cast<const char *>(orig), size, &encodedLength);
    char *decoded = base64.Decode(encoded, encodedLength, &decodedLength);
    printbytes("O", decoded, decodedLength); printf("\r\n");

    TEST_ASSERT_EQUAL_INT(size, decodedLength);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(orig, decoded, size);

    delete[] orig;
    delete[] encoded;
    delete[] decoded;

    return (n < 4) ? CaseRepeatAll : CaseNext;
}


utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(200, "default_auto");
    return greentea_test_setup_handler(number_of_cases);
}


int main() {
    Case cases[] = {
            Case("Base64 RFC 4648 test vectors", TestBase64RFC4648, greentea_case_failure_abort_handler),
            Case("Base64 size power of 2 test", TestBase64PowerOfTwo, greentea_case_failure_abort_handler),
            Case("Base64 size power of 2+1 test", TestBase64PowerOfTwoPlusOne, greentea_case_failure_abort_handler),

    };

    Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);
    Harness::run(specification);
}