import unittest
from encryption_manager import EncryptionManager
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
import json
from Crypto.Signature import PKCS1_v1_5
import warnings


class SymmetricTest(unittest.TestCase):
    def get_pub_key(self):
        with open("server_pub.PEM") as key_file:
            return key_file.read()

    def get_priv_key(self):
        with open("server_priv.PEM") as key_file:
            return key_file.read()

    def test_symmetric(self):
        encryption = EncryptionManager()
        ptxt = "hello world!"
        ctxt, key, iv= encryption.encrypt_symmetric(ptxt)
        key = encryption.hex_to_bytes(key)
        iv = encryption.hex_to_bytes(iv)
        ctxt = encryption.hex_to_bytes(ctxt)
        result = encryption.decrypt_symmetric_w_params(ctxt, key, iv).decode("utf-8")
        self.assertEqual(result, ptxt)

    def test_asymmetric(self):
        ptxt = "hello world!"
        rsa = RSA.importKey(self.get_pub_key())
        rsa = PKCS1_OAEP.new(rsa)
        ctxt = rsa.encrypt(ptxt.encode())
        rsa = RSA.importKey(self.get_priv_key())
        rsa = PKCS1_OAEP.new(rsa)
        result = rsa.decrypt(ctxt).decode('utf-8')
        self.assertEqual(result, ptxt)

    def test_signing(self):
        encryption = EncryptionManager()
        ptxt = "hello world!"
        sig = encryption.sign_message(ptxt, self.get_priv_key())
        sig = encryption.hex_to_bytes(sig)
        result = encryption.verify_message(ptxt, self.get_pub_key(), sig)
        self.assertEqual(result, True)


if __name__ == '__main__':
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', category=DeprecationWarning)
        unittest.main()
