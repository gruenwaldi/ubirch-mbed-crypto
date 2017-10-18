/*!
 * @file
 * @brief TODO: ${FILE}
 *
 * ...
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

#include "KeyPair.h"

ED25519KeyPair::ED25519KeyPair() : KeyPair(), generated(false) {}

ED25519KeyPair::~ED25519KeyPair() {
    if (generated) {
        delete privateKey;
        delete publicKey;
    }
}

void ED25519KeyPair::generate() {
    generated = true;

    publicKey = new ED25519PublicKey();
    privateKey = new ED25519PrivateKey();
    memset(publicKey->key, 0, sizeof(ED25519PublicKey));
    memset(privateKey->key, 0, sizeof(ED25519PrivateKey));

    crypto_sign_keypair(publicKey->key, privateKey->key);
}

ED25519PublicKey *ED25519KeyPair::getPublicKey() {
    return publicKey;
}

void ED25519KeyPair::link(const ED25519PublicKey *publicKey, const ED25519PrivateKey *privateKey) {
    this->publicKey = const_cast<ED25519PublicKey *>(publicKey);
    this->privateKey = const_cast<ED25519PrivateKey *>(privateKey);
}

void ED25519KeyPair::import(const ED25519PublicKey &publicKey, const ED25519PrivateKey &privateKey) {
    if (this->publicKey == NULL) this->publicKey = new ED25519PublicKey();
    if (this->privateKey == NULL) this->privateKey = new ED25519PrivateKey();

    memcpy(this->publicKey->key, publicKey.key, crypto_sign_PUBLICKEYBYTES);
    memcpy(this->privateKey->key, privateKey.key, crypto_sign_SECRETKEYBYTES);

    generated = true;
}

unsigned char *ED25519KeyPair::sign(const unsigned char *message, size_t length) {
    if (privateKey == NULL) return NULL;

    // sign the message
    crypto_uint16 signedLength;
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + length];
    crypto_sign(signedMessage, &signedLength,
                reinterpret_cast<const unsigned char *>(message), static_cast<crypto_uint16>(length),
                privateKey->key);

    // extract the signature
    unsigned char *signature = new unsigned char[crypto_sign_BYTES];
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    delete[] signedMessage;

    return signature;
}

bool ED25519KeyPair::verify(const unsigned char *message, size_t length, const unsigned char *signature) {
    if(publicKey == NULL) return false;
    if ((message == NULL) || (length == 0) || (signature == NULL)) return false;

    // allocate signed message buffer and verificationBuffer (both must be length + signature length!)
    // internally the NaCl library uses the verification buffer as a playground
    const size_t signedMessageLength = crypto_sign_BYTES + length;
    unsigned char *signedMessage = new unsigned char[signedMessageLength];
    unsigned char *verifiedMessage = new unsigned char[signedMessageLength];

    memcpy(signedMessage, signature, crypto_sign_BYTES);
    memcpy(signedMessage + crypto_sign_BYTES, message, length);
    memset(verifiedMessage, 0, signedMessageLength);

    crypto_uint16 verifiedMessageLength;
    bool sigVerified = !crypto_sign_open(verifiedMessage, &verifiedMessageLength,
                                        signedMessage, static_cast<crypto_uint16>(crypto_sign_BYTES + length),
                                        publicKey->key);

    bool msgVerified = verifiedMessageLength == length && !memcmp(message, verifiedMessage, length);

    delete[] signedMessage;
    delete[] verifiedMessage;

    return sigVerified && msgVerified;
}


