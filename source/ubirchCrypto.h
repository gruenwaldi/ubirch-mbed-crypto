//
// Created by wowa on 04.10.17.
//

#ifndef TRACKLE_FIRMWARE_UBIRCHCRYPTO_H
#define TRACKLE_FIRMWARE_UBIRCHCRYPTO_H

#include <common.h>
#include "../../ubirch-mbed-nacl-cm0/source/nacl/armnacl.h"

class crypto {

public:

    /*!
     * @brief   Constructor
     */
    crypto();

    /*!
     * @brief   Destructor
     */
    ~crypto();

    /*!
     * @brief   Create a new Key Pair.
     *
     * @return  true
     */
    bool createKeyPair(void);

    /*!
     * @brief   Sign a Message with the secret Key.
     *
     * @param message       message buffer
     * @param messageLength length of the message buffer
     * @return  Signature of the message buffer[crypto_sign_BYTES]
     *
     * @note    The returned buffer has to be deleted after usage.
     */
    unsigned char *signMessage(const unsigned char *message, uint16_t messageLength);

    /*!
     * @brief   Sign a message with secret Key and encode it with base64
     *
     * @param message       message buffer
     * @param messageLength length of message buffer
     * @return  Signed and base64 encoded message
     *
     * @note    The returned buffer has to be deleted after usage
     */
    unsigned char *signMessageEncoded(const unsigned char *message, uint16_t messageLength);

    /*!
     * @brief   Verify the signed message with the public key.
     *
     * @param signature     signed message buffer
     * @param message       message buffer
     * @param messageLength length of message buffer
     *
     * @return  true if successful, else false

     */
    bool verifySignature(const unsigned char *signature, const unsigned char *message, uint16_t messageLength);

    /*!
     * @brief Provide the public Key for the Key Service in JSON.
     *
     * @return JSON string of current key
     *
     * @note    The returned buffer has to be deleted after usage.
     */
    unsigned char *provideKeyJson(void);

    /*!
     * @brief       Encode a message with base64 encoding.
     *
     * @param message       message buffer
     * @param messageLength length of message buffer
     * @return      encoded message in base64 format if successful, else NULL
     *
     * @note    The returned buffer has to be deleted after usage.
     */
    unsigned char *encodeMessageBase64(const unsigned char *message, uint16_t messageLength);


    /*!
     * @brief       Decode a message from base64 encoded to binary.
     *
     * @param message       message buffer
     * @param messageLength length of message buffer
     *
     * @return      decoded message in binary format if successful, else NULL
     *
     * @note    The returned buffer has to be deleted after usage.
     */
    unsigned char *decodeMessageBase64(const unsigned char *message, uint16_t messageLength);


    bool importPublicKey(const unsigned char *publicKey);


    /*!
     * @brief       get the public Key.
     *
     * @return      public Key array
     */
    const unsigned char *getMyPublicKey() const;

    const unsigned char *getBackendPublicKey() const;

    const unsigned char *getBackendSignature() const;

//    bool storeKeyPair(){};

private:
    // my Keys
    unsigned char myPublicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char mySecretKey[crypto_sign_SECRETKEYBYTES];

    // Backend Keys
    unsigned char backendPublicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char backendSignature[crypto_sign_BYTES];
};


#endif //TRACKLE_FIRMWARE_UBIRCHCRYPTO_H

