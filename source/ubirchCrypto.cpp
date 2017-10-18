//
// Created by wowa on 04.10.17.
//

#include <cstdio>
#include <cstring>
#include <ctime>
#include "ubirchCrypto.h"
#include "Base64.h"

#define PRINTF(...)     printf(__VA_ARGS__)

/*
unsigned char *crypto::provideKeyJson() {
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
    */
/*
     * TODO error management
     *//*

    return NULL;
}
*/




