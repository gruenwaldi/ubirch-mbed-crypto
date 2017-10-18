import base64

from mbed_host_tests import BaseHostTest, event_callback
import ed25519


class CryptoProtocolTests(BaseHostTest):

    @event_callback("importPublicKey")
    def __importKey(self, key, value, timestamp):
        self.vk = ed25519.VerifyingKey(value, encoding="base64")

    @event_callback("expectedMessageLength")
    def __expectedMessageLength(self, key, value, timestamp):
        self.messageLength = int(value)

    @event_callback("verifySignature")
    def __verifySignature(self, key, value, timestamp):
        data = value.decode('base64')
        message = data[0:self.messageLength]
        signature = data[self.messageLength:]
        self.log("message  =" + message.encode('hex'))
        self.log("signature=" + signature.encode('hex'))
        try:
            self.log("public key: " + self.vk.to_bytes().encode('base64'))
            self.vk.verify(signature, message)
            self.send_kv("verify", "OK")
        except Exception as e:
            self.send_kv("error", e.message)

    @event_callback("signMessage")
    def __signMessage(self, key, value, timestamp):
        message = value.decode('base64')
        self.log(message.encode('hex'))
        
        sk = ed25519.SigningKey(
            "88429AD250445554D4C09A9AA16CC992F350D46DA08F588F41E83EF2AF09CAA01325816B2A20F4C3C1C5267D0DC6CFF5FCE4B8A045853D62F8C7239DF03F852E",
            encoding='hex')
        signature = sk.sign(message)
        signatureEncoded = base64.b64encode(signature)
        self.log("signature["+str(len(signature))+"]=" + signatureEncoded)

        # send the data in slices
        for pos in xrange(0, len(signatureEncoded), 20):
            self.send_kv("signature", signatureEncoded[pos:pos + 20])