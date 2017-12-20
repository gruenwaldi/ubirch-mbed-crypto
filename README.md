# ubirch-mbed-crypto

[ubirch](https://ubirch.com) crypto library. Sign and encrypt messages.

# Testing

```bash
mbed new .
mbed target NRF52_DK
mbed toolchain GCC_ARM
mbed test -n tests-crypto*
```

## Test Results:

### Nordic NRF52 DK
```
+------------------+---------------+-----------------------+--------+--------------------+-------------+
| target           | platform_name | test suite            | result | elapsed_time (sec) | copy_method |
+------------------+---------------+-----------------------+--------+--------------------+-------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-base64   | OK     | 157.31             | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | OK     | 56.91              | default     |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-protocol | OK     | 28.52              | default     |
+------------------+---------------+-----------------------+--------+--------------------+-------------+
mbedgt: test suite results: 3 OK
mbedgt: test case report:
+------------------+---------------+-----------------------+------------------------------------------+--------+--------+--------+--------------------+
| target           | platform_name | test suite            | test case                                | passed | failed | result | elapsed_time (sec) |
+------------------+---------------+-----------------------+------------------------------------------+--------+--------+--------+--------------------+
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-base64   | Base64 RFC 4648 test vectors             | 1      | 0      | OK     | 0.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-base64   | Base64 size power of 2 test              | 4      | 0      | OK     | 36.43              |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-base64   | Base64 size power of 2+1 test            | 4      | 0      | OK     | 36.42              |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test generate keypair             | 1      | 0      | OK     | 0.92               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test import keypair               | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test import keypair from arrays   | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test import public key from array | 1      | 0      | OK     | 0.08               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test set keypair                  | 1      | 0      | OK     | 0.05               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test sign message                 | 5      | 0      | OK     | 1.32               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test sign/verify self             | 5      | 0      | OK     | 3.07               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-keys     | Crypto test verify message               | 5      | 0      | OK     | 2.01               |
| NRF52_DK-GCC_ARM | NRF52_DK      | tests-crypto-protocol | Crypto test key exchange                 | 1      | 0      | OK     | 9.87               |
+------------------+---------------+-----------------------+------------------------------------------+--------+--------+--------+--------------------+
```

#### UBRIDGE (NXP K82F)
```
+-----------------+---------------+-----------------------+--------+--------------------+-------------+
| target          | platform_name | test suite            | result | elapsed_time (sec) | copy_method |
+-----------------+---------------+-----------------------+--------+--------------------+-------------+
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-base64   | OK     | 215.76             | default     |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | OK     | 49.73              | default     |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-protocol | OK     | 29.52              | default     |
+-----------------+---------------+-----------------------+--------+--------------------+-------------+
mbedgt: test suite results: 3 OK
mbedgt: test case report:
+-----------------+---------------+-----------------------+------------------------------------------+--------+--------+--------+--------------------+
| target          | platform_name | test suite            | test case                                | passed | failed | result | elapsed_time (sec) |
+-----------------+---------------+-----------------------+------------------------------------------+--------+--------+--------+--------------------+
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-base64   | Base64 RFC 4648 test vectors             | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-base64   | Base64 size power of 2 test              | 4      | 0      | OK     | 51.41              |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-base64   | Base64 size power of 2+1 test            | 4      | 0      | OK     | 51.54              |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test generate keypair             | 1      | 0      | OK     | 0.66               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test import keypair               | 1      | 0      | OK     | 0.05               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test import keypair from arrays   | 1      | 0      | OK     | 0.07               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test import public key from array | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test set keypair                  | 1      | 0      | OK     | 0.06               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test sign message                 | 5      | 0      | OK     | 1.65               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test sign/verify self             | 5      | 0      | OK     | 1.71               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-keys     | Crypto test verify message               | 5      | 0      | OK     | 2.07               |
| UBRIDGE-GCC_ARM | UBRIDGE       | tests-crypto-protocol | Crypto test key exchange                 | 1      | 0      | OK     | 8.19               |
+-----------------+---------------+-----------------------+------------------------------------------+--------+--------+--------+--------------------+
```

### Key Exchange Test

This test is a proof-of-concept for the key exchange. It assumes
that the transport layer is encrypted, so it is simplified to use
signatures only.

The test consists of an on-device device part found in `TESTS/crypto/protocol/KeyExchangeTests.cpp`
as well as a host (PC) side test found in `TESTS/host_tests/KeyExchangeTests.py`.
Both communicate via the serial line to pass messages back and forth:

* STEP 1: device sends its message signed (includes device-pub, nonce), server keeps device-pubkey
* STEP 2: server sends its message signed (includes server-pub, nonce), device keeps server-pub
* STEP 3: server sends device message signed back (includes device-pub, nonce)
* STEP 4: device sends server message signed back (includes server-pub, nonce)

```
STEP 1 (D->S)
SERVER <--------------(D[D])------------- DEVICE
STEP 2 (S->D)
SERVER ---------------(S[S])------------> DEVICE
STEP 3 (S->D)
SERVER ---------------(S[D])------------> DEVICE
STEP 4 (D->S)
SERVER <--------------(D[S])------------- DEVICE
```

If everything is correct, both will have a verified version of the partners public key.
