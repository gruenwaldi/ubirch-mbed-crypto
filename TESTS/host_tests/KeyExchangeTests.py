import base64
from time import sleep

import msgpack
import os
from mbed_host_tests import BaseHostTest, event_callback
import ed25519


class CryptoProtocolTests(BaseHostTest):
    """
    Crypto Protocol - This is the server side.

    The key exchange usually includes a device id for assigned the key to
    check it and for checking the backend key storage. It is not needed for
    this test.

    [devicePubKey:nonce:signature]
     0---------31:32-35:36----100


     STEP 1: device sends its message signed (includes device-pub, nonce), server keeps device-pubkey
     STEP 2: server sends its message signed (includes server-pub, nonce), device keeps server-pub
     STEP 3: server sends device message signed back (includes device-pub, nonce)
     STEP 4: device sends server message signed back (includes server-pub, nonce)

     If everything is correct, both will have a verified version of the partners public key.
    """

    def __init__(self):
        # generate key pair (server side)
        self.private, self.public = ed25519.create_keypair(entropy=os.urandom)
        BaseHostTest.__init__(self)

    @event_callback("deviceSignedDeviceMessage")
    def __step1_2_3(self, key, value, timestamp):
        # STEP 1 - receive device signed device message
        self.log("SERVER <--------------(D[D])------------- DEVICE")
        deviceSignedDeviceMessage = value.decode("base64")
        self.log("** signed message length: "+str(len(deviceSignedDeviceMessage)))

        # extract required parts of the device signed device message (Dpub,Dnonce)-tuple
        deviceMessage = deviceSignedDeviceMessage[0:36]
        devicePubKey = deviceSignedDeviceMessage[0:32]
        deviceNonce = deviceSignedDeviceMessage[32:36]
        deviceSignature = deviceSignedDeviceMessage[36:]
        self.log("** devicePubKey=["+str(len(devicePubKey))+"] " + devicePubKey.encode('hex') + ", nonce=["+str(len(deviceNonce))+"] " + deviceNonce.encode('hex'))
        self.log("** deviceSignature=["+str(len(deviceSignature))+"] "+deviceSignature.encode('hex'))

        # check the device signed message and send back a server signed copy
        try:
            # remember the device public key
            self.deviceVerifyingKey = ed25519.VerifyingKey(devicePubKey)
            self.deviceVerifyingKey.verify(deviceSignature, bytes(deviceMessage))
        except ed25519.BadSignatureError:
            self.send_kv("error", "VERIFICATION FAILED")
            return
        except Exception as e:
            self.send_kv("error", e.message)
            return

        # STEP 2 - send server signed server message
        serverPubKey = self.public.to_bytes()
        serverNonce = os.urandom(4)
        self.serverMessage = serverPubKey + serverNonce
        serverSignature = self.private.sign(bytes(self.serverMessage))
        serverSignedServerMessage = self.serverMessage + serverSignature
        encodedServerSignedServerMessage = base64.b64encode(serverSignedServerMessage)
        self.log("** serverPubKey=["+str(len(serverPubKey))+"] " + serverPubKey.encode('hex') + ", nonce=["+str(len(serverNonce))+"] " + serverNonce.encode('hex'))
        self.log("** serverSignature=["+str(len(serverSignature))+"] "+serverSignature.encode('hex'))
        # send the data in slices
        for pos in xrange(0, len(encodedServerSignedServerMessage), 30):
            self.send_kv("serverSignedServerMessage", encodedServerSignedServerMessage[pos:pos+30])
        self.log("SERVER ---------------(S[S])------------> DEVICE")


        # STEP 3 - send server signed device message
        serverSignature = self.private.sign(deviceMessage)
        serverSignedDeviceMessage = deviceMessage + serverSignature
        encodedServerSignedDeviceMessage = base64.b64encode(serverSignedDeviceMessage)
        self.log("** serverSignature=["+str(len(serverSignature))+"] "+serverSignature.encode('hex'))
        # send the data in slices
        for pos in xrange(0, len(encodedServerSignedDeviceMessage), 30):
            self.send_kv("serverSignedDeviceMessage", encodedServerSignedDeviceMessage[pos:pos+30])
        self.log("SERVER ---------------(S[D])------------> DEVICE")

    @event_callback("deviceSignedServerMessage")
    def __step4(self, key, value, timestamp):
        # STEP 4 - receive device signed server message
        self.log("SERVER <--------------(D[S])------------- DEVICE")
        deviceSignedServerMessage = value.decode("base64")
        self.log("** signed message length: "+str(len(deviceSignedServerMessage)))

        # extract required parts of the device signed server message (Dpub,Dnonce)-tuple
        serverMessage = deviceSignedServerMessage[0:36]
        deviceSignature = deviceSignedServerMessage[36:]

        # check the device signed server message and report server side success
        try:
            if self.serverMessage != serverMessage: raise Exception("server message changed")
            self.deviceVerifyingKey.verify(deviceSignature, bytes(serverMessage))
            self.send_kv("serverVerification", "SUCCESS")
        except ed25519.BadSignatureError:
            self.send_kv("error", "VERIFICATION FAILED")
            return
        except Exception as e:
            self.send_kv("error", e.message)