/*!
 * @file
 * @brief Key pair handling.
 *
 * This class abstracts a public/private key pair as well as
 * a version that uses ED25519 as the underlying algorithm.
 *
 * @author Matthias L. Jugel
 * @date   2017-10-17
 *
 * @copyright &copy; 2017 ubirch GmbH (https://ubirch.com)
 *
 * @section LICENSE
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

#ifndef UBIRCH_MBED_CRYPTO_KEYPAIR_H
#define UBIRCH_MBED_CRYPTO_KEYPAIR_H

#include <nacl/armnacl.h>
#include <cstring>
#include <cstdio>

/**
 * The KeyPair can have arbitrary types as public and private keys.
 *
 * @tparam PUBLIC the public key type, e.g. unsigned char ed25519pub[crypto_sign_PUBLICKEYBYTES]
 * @tparam PRIVATE the private key type, e.g. unsigned char ed25519priv[crypto_sign_SECRETKEYBYTES]
 */
template<class PUBLIC, class PRIVATE>
class KeyPair {
protected:
    PUBLIC *publicKey;
    PRIVATE *privateKey;

public:
    /**
     * Initialize an empty key pair.
     */
    KeyPair() : publicKey(NULL), privateKey(NULL) {};

    /**
     * Generate the public/private key pair using the
     * configured algorithm.
     */
    virtual void generate() = 0;

    /**
     * Get a pointer to the public key.
     * @return a pointer to the public key.
     */
    virtual PUBLIC *getPublicKey() = 0;
};

typedef struct ED25519PublicKey {
    unsigned char key[crypto_sign_PUBLICKEYBYTES];
} ED25519PublicKey;

typedef struct ED25519PrivateKey {
    unsigned char key[crypto_sign_SECRETKEYBYTES];
} ED25519PrivateKey;

typedef struct ED25519Signature {
    unsigned char signature[crypto_sign_BYTES];
} ED25519Signature;

/**
 * A class holding an ED25519 key pair.
 */
class ED25519KeyPair : public KeyPair<ED25519PublicKey, ED25519PrivateKey> {
public:
    ED25519KeyPair();

    ~ED25519KeyPair();

    /**
     * Generate a new ED25519 key pair.
     */
    void generate();

    ED25519PublicKey *getPublicKey();

    /**
     * Link to an existing storage location of an ED25519 key pair.
     * The private key may be ignored if only the public key will be used.
     * @param publicKey a pointer to the public key
     * @param privateKey a pointer to the private key
     */
    void link(const ED25519PublicKey *publicKey, const ED25519PrivateKey *privateKey = NULL);

    /**
     * Import an ED25519 key pair. Both keys will be copied into an internal structure.
     * @param publicKey the public key
     * @param privateKey the private key
     */
    void import(const ED25519PublicKey &publicKey, const ED25519PrivateKey &privateKey);

    /**
     * Import an ED25519  key pair from a char arrays.
     * @param publicKey
     * @param length
     */
    bool import(const unsigned char *publicKey, int pubKeyLength, const unsigned char *privateKey, int privKeyLength) {
        if (publicKey == NULL || pubKeyLength != crypto_sign_PUBLICKEYBYTES ||
            privateKey == NULL || privKeyLength != crypto_sign_SECRETKEYBYTES)
            return false;

        importPublicKey(publicKey, pubKeyLength);

        if (this->privateKey == NULL) this->privateKey = new ED25519PrivateKey();
        memcpy(this->privateKey->key, privateKey, crypto_sign_SECRETKEYBYTES);

        return true;
    }

    /**
     * Import an ED25519 public key from a char array.
     * @param publicKey
     * @param length
     */
    bool importPublicKey(const unsigned char *publicKey, int length) {
        if (publicKey == NULL || length != crypto_sign_PUBLICKEYBYTES) return false;

        if (this->publicKey == NULL) this->publicKey = new ED25519PublicKey();
        memcpy(this->publicKey->key, publicKey, crypto_sign_PUBLICKEYBYTES);

        return true;
    }


    /**
     * Sign a message using the ED25519 private key.
     * @param message the message to sign
     * @param length the length of the message to sign, don't rely on \0 termination
     * @param signature the signature to check the message
     * @returns the signature
     * @returns NULL if the private key is not available
     */
    unsigned char *sign(const unsigned char *message, size_t length);

    bool verify(const unsigned char *message, size_t length, const unsigned char *signature);

private:
    bool generated;
};

#endif //UBIRCH_MBED_CRYPTO_KEYPAIR_H
