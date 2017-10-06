//
// Created by wowa on 04.10.17.
//

#include <cstdio>
#include <cstring>
#include <ctime>
#include <nrf52.h>
#include "ubirchCrypto.h"
#include "../../dbgutil/dbgutil.h"
#include "../arduino-base64/Base64.h"

#define KEY_HNDL_DBG 0


crypto::crypto() {}

crypto::~crypto() {}

bool crypto::createKeyPair(void) {

    crypto_sign_keypair(myPublicKey, mySecretKey);
    PRINTF("PubKey = ");
#if (!NOPRINTF)
    for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++) {
        PRINTF(" %2X", myPublicKey[i]);
    }
    PRINTF("\r\nSecKey = ");
    for (int i = 0; i < crypto_sign_SECRETKEYBYTES; i++) {
        PRINTF(" %2X", mySecretKey[i]);
    }
    PRINTF("\r\n");
#endif
    return true;
}


unsigned char *crypto::signMessage(const unsigned char *message, uint16_t messageLength) {
    if ((message == NULL) || messageLength == 0){
        PRINTF("ERROR: input buffer empty\r\n");
        return NULL;
    }
    crypto_uint16 signedLength = messageLength + crypto_sign_BYTES;
    unsigned char *signedMessage = new unsigned char[signedLength + 1];

    // this function signs the message and returns the signature combined with the message [signature, message]
    crypto_sign(signedMessage, &signedLength, message, (crypto_uint16) (messageLength), mySecretKey);

    // extract the signature
    unsigned char *signature = new unsigned char[crypto_sign_BYTES + 1];
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    signature[crypto_sign_BYTES] = '\0';
    delete signedMessage;

#if (!NOPRINTF)
    PRINTF("SIGNING MESSAGE \r\n");
    PRINTF("message = ");
    for (int i = 0; i < messageLength; i++) {
        PRINTF(" %02X", message[i]);
    }
    PRINTF("\r\nSignature = ");
    for (int i = 0; i < crypto_sign_BYTES; i++) {
        PRINTF(" %02X", signature[i]);
    }
    PRINTF("\r\n");
#endif

    return signature;
}

unsigned char *crypto::signMessageEncoded(const unsigned char *message, uint16_t messageLength) {
    // sign the message
    unsigned char *signedMessage = this->signMessage(message, messageLength);
    // encoded the signed message
    uint16_t signedLength = strlen((const char *) (signedMessage));

    return this->encodeMessageBase64(signedMessage, signedLength);
}


bool crypto::verifySignature(const unsigned char *signature, const unsigned char *message, uint16_t messageLength) {
    if((signature == NULL) || (message == NULL) || (messageLength == 0)){
        PRINTF("ERROR: empty input buffer or length = 0\r\n");
        return false;
    }
    // create new buffer with complete message (signature + message)
    crypto_uint16 fullMessageLength = crypto_sign_BYTES + messageLength;
    unsigned char *fullMessage = new unsigned char[fullMessageLength + 1];
    memcpy(fullMessage, signature, crypto_sign_BYTES);
    memcpy((fullMessage + crypto_sign_BYTES), message, messageLength);
    fullMessage[fullMessageLength] = '\0';
    // create new buffer for the message to compare
    unsigned char *compareMessage = new unsigned char[fullMessageLength + 1];
    uint16_t compareLength;
    // TODO check if backend key is available
    int ret = crypto_sign_open(compareMessage, &compareLength, fullMessage, fullMessageLength, backendPublicKey);
    if (ret == -1) { // TODO check this output
        PRINTF("************************\r\n*** ERROR ***\r\n*******************\r\n");
        return false;
    } else {
#if (!NOPRINTF)
        PRINTF("VERIFYING SIGNATURE \r\n");
        PRINTF("SignedMessage = ");
        for (int i = 0; i < crypto_sign_BYTES; i++) {
            PRINTF(" %02X", signature[i]);
        }
        PRINTF("\r\nmessage = ");
        for (int i = 0; i < fullMessageLength; i++) {
            PRINTF(" %02X", fullMessage[i]);
        }
        PRINTF("\r\n");
#endif
    }
    // compare the length and the messages
    ret = strncmp((const char*)(message), (const char*)(compareMessage), messageLength);
//    PRINTF("\r\n##########\r\n ret = %d\r\n########\r\n", ret);
    if(ret || (compareLength != messageLength)){
        return false;
    }
    delete fullMessage;
    delete compareMessage;

    return true;
}

unsigned char *crypto::provideKeyJson(void) {
    PRINTF("\r\n>>>provideKeyJSON \r\n");
    // get the time of creation
    time_t timestamp = time(NULL);
    struct tm *tm1 = localtime(&timestamp);
    static const char *const timeStamp_template = "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ"; //“2017-05-09T10:25:41.836Z”

    // make a  time string in ISO 8601 format
    int time_size = snprintf(NULL, 0, timeStamp_template, tm1->tm_year + 1900, tm1->tm_mon + 1, tm1->tm_mday,
                             tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    char *created = new char[time_size + 1];
    sprintf(created, timeStamp_template, tm1->tm_year + 1900, tm1->tm_mon + 1, tm1->tm_mday,
            tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    // TODO fraction seconds is always 0, do we need it?
    PRINTF("created = %s\r\n", created);

    // set the validation from to the time of creation
    char *validNotBefore = new char[time_size + 1];
    sprintf(validNotBefore, timeStamp_template, tm1->tm_year + 1900, tm1->tm_mon + 1, tm1->tm_mday,
            tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    //TODO same as created time
    PRINTF("validnotbefore = %s\r\n", validNotBefore);

    // set the validation to to the time of creation + 5 years
    char *validNotAfter = new char[time_size + 1];
    sprintf(validNotAfter, timeStamp_template, tm1->tm_year + 1900 + 5, tm1->tm_mon + 1, tm1->tm_mday,
            tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    //TODO same as created time + 5 years
    PRINTF("validnotafter = %s\r\n", validNotAfter);

    // get the device ID
    uint32_t deviceUUID[4];
    deviceUUID[0] = NRF_FICR->DEVICEADDR[0];
    deviceUUID[1] = NRF_FICR->DEVICEADDR[1];
    deviceUUID[2] = NRF_FICR->DEVICEID[0];
    deviceUUID[3] = NRF_FICR->DEVICEID[1];

    // make a string out of the device id
    int hwIdSize = snprintf(NULL, 0, "%lu-%lu-%lu-%lu", deviceUUID[0], deviceUUID[1], deviceUUID[2], deviceUUID[3]);
    char *hwDeviceId = new char[hwIdSize + 1];
    sprintf(hwDeviceId, "%lu-%lu-%lu-%lu", deviceUUID[0], deviceUUID[1], deviceUUID[2], deviceUUID[3]);
    PRINTF("hwDeviceId = %s\r\n", hwDeviceId);

    // get the key
    char *pubKey = (char *) (this->encodeMessageBase64(myPublicKey, crypto_sign_PUBLICKEYBYTES));

//	char *hwDeviceId = "";
//	char *pubKey = "";
    char *pubKeyId = {""};                    // TODO add keyID
    char *algorithm = {"ECC_ED25519"};
    char *previousPubKeyId = {""};            // TODO add previous keyID
//	char *created = "";
//	char *validNotBefore = "";
//	char *validNotAfter = "";
//	char signature[SIG_SIZE];
    char *previousPubKeySignature = {""};    //TODO add previous signature

    // create the JSON for pubKeyInfo
    static const char *const pubKeyInfo_template = "{"
            "\"hwDeviceId\":\"%s\","
            "\"pubKey\":\"%s\","
            "\"pubKeyId\":\"%s\","
            "\"algorithm\":\"%s\","
            "\"previousPubKeyId\":\"%s\","
            "\"created\":\"%s\","
            "\"validNotBefore\":\"%s\","
            "\"validNotAfter\":\"%s\""
            "}";

    int pubKeyInfoSize = snprintf(NULL, 0, pubKeyInfo_template, hwDeviceId, pubKey, pubKeyId, algorithm,
                                  previousPubKeyId, created, validNotBefore, validNotAfter);
    char *pubKeyInfo = new char[pubKeyInfoSize + 1];
    sprintf(pubKeyInfo, pubKeyInfo_template, hwDeviceId, pubKey, pubKeyId, algorithm,
            previousPubKeyId, created, validNotBefore, validNotAfter);
    PRINTF("pubKeyInfo = %s\r\n", pubKeyInfo);


    // sign PubKeyInfo
    char *signature = (char *) (this->signMessageEncoded((const unsigned char *) (pubKeyInfo), pubKeyInfoSize));

    static const char *const message_template = "{"
            "\"pubKeyInfo\":%s,"
            "\"signature\":\"%s\","
            "\"previousPubKeySignature\":\"%s\""
            "}";

    // create the complete JSON
    int messageSize = snprintf(NULL, 0, message_template, pubKeyInfo, signature, previousPubKeySignature);
    char *message = new char[messageSize + 1];
    sprintf(message, message_template, pubKeyInfo, signature, previousPubKeySignature);
    PRINTF("message (%u) = %s\r\n", (uint16_t) strlen((const char *) (message)), message);


#if KEY_HNDL_DBG
    printf("ID              : %s\r\n", hwDeviceId);
    printf("KEY             : %s\r\n", pubKey);
    printf("KEY ID          : %s\r\n", pubKeyId);
    printf("ALGO            : %s\r\n", algorithm);
    printf("PREV KEY ID     : %s\r\n", previousPubKeyId);
    printf("CREATED         : %s\r\n", created);
    printf("VALID FROM      : %s\r\n", validNotBefore);
    printf("VALID TO        : %s\r\n", validNotAfter);
    printf("SIGNATURE       : %s\r\n", signature);
    printf("PREV SIGN       : %s\r\n", previousPubKeySignature);
#endif
    // free the memory
    delete (hwDeviceId);
    delete (created);
    delete (validNotBefore);
    delete (validNotAfter);
    delete (pubKeyInfo);
    // TODO deallocate the memory, and add documentation

    return (unsigned char *) (message);
    /*
     * TODO error management
     */
    return NULL;
}


unsigned char *crypto::encodeMessageBase64(const unsigned char *message, uint16_t messageLength) {
    int encodedLength = base64_enc_len(messageLength);
    unsigned char *encodedMessage = new unsigned char[encodedLength + 1];
    if (encodedLength == base64_encode((char *) (encodedMessage), (char *) (message), messageLength)) {
        return encodedMessage;
    } else {
        PRINTF("ENCODING FAILED \r\n");
        return NULL;
    }
}


const unsigned char *crypto::getMyPublicKey() const {
    return myPublicKey;
}

const unsigned char *crypto::getBackendPublicKey() const {
    return backendPublicKey;
}

const unsigned char *crypto::getBackendSignature() const {
    return backendSignature;
}



unsigned char *crypto::decodeMessageBase64(const unsigned char *message, uint16_t messageLength) {
    int decodedLength = base64_dec_len((char *) (message), messageLength);
    unsigned char *decodedMessage = new unsigned char[decodedLength + 1];
    if (decodedLength == base64_decode((char *) (decodedMessage), (char *) (message), messageLength)) {
        return decodedMessage;
    } else {
        PRINTF("DECODING FAILED\r\n");
        return NULL;
    }
}

bool crypto::importPublicKey(const unsigned char *publicKey) {
    if (publicKey == NULL) {
        return false;
    }
    memcpy(backendPublicKey, publicKey, crypto_sign_PUBLICKEYBYTES);
    return true;
}




