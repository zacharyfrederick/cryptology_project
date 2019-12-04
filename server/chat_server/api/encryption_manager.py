from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

class EncryptionManager:
    """Test summary of the encryption manager
    """
    def __init__(self):
        pass

    def get_iv(self, hex=False):
        if hex:
            return get_random_bytes(16).hex()
        else:
            return get_random_bytes(16)

    def get_symmetric_key(self, hex=False):
        if hex:
            return get_random_bytes(32).hex()
        else:
            return get_random_bytes(32)

    def encrypt_symmetric(self, raw_data):
        iv = self.get_iv()
        key = self.get_symmetric_key()
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ctxt = cipher.encrypt(raw_data)
        return (ctxt.hex(), key.hex(), iv.hex())

    def create_encrypted_key_data(self, raw_data):
        raw_data = self.process_dict_for_encry(raw_data)
        ctxt, key, iv = self.encrypt_symmetric(raw_data)

        with open("server_pub.PEM", 'r') as key_file:
            rsa = RSA.importKey(key_file.read())
            rsa = PKCS1_OAEP.new(rsa)
            key_data = {"key": key, "iv": iv}
            key_data = self.process_dict_for_encry(key_data, encode=True)
            try:
                key_data = rsa.encrypt(key_data).hex()
                return (ctxt, key_data)
            except Exception as e:
                print(e)
            
    def process_dict_for_encry(self, raw_data, encode=False):
        try:
            test = json.dumps(raw_data)
            if encode:
                return test.encode()
            else:
                return test
        except:
            print("Some error")

    def hex_to_bytes(self, data):
        return bytes(bytearray.fromhex(data))

    def decrypt_key_data(self, key_data):
        with open("server_priv.PEM", 'r') as key_file:
            rsa = RSA.importKey(key_file.read())
            rsa = PKCS1_OAEP.new(rsa)
            ptxt = json.loads(rsa.decrypt(key_data).decode("utf-8"))
            return ptxt

    def decrypt_contents(self, contents, key, iv):
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return json.loads(cipher.decrypt(contents).decode("utf-8"))

    def extract_key_data_contents(self, key_data):
        key = self.hex_to_bytes(key_data['key'])
        iv = self.hex_to_bytes(key_data['iv'])
        return (key, iv)

    def extract_user_data(self, contents):
        username = contents['username']
        pub_key = contents['pub_key']
        ip = contents['ip']
        port = contents['port']
        return (username, pub_key, ip, port)
    
    def sign_message(self, msg, priv_key):
        msg = msg.encode()
        try:
            rsa = RSA.importKey(priv_key)
            hashed_msg = SHA.new(msg)
            signer = PKCS1_v1_5.new(rsa)
            signature = signer.sign(hashed_msg)
            return signature.hex()
        except Exception as e:
            print(e)

    def verify_message(self, msg, pub_key, signature):
        rsa = RSA.importKey(pub_key)
        h = SHA.new(msg.encode())
        verifier = PKCS1_v1_5.new(rsa)
        return verifier.verify(h, signature)

    def process_register_data(self, raw_data):
        """Processes the registration data sent to the server as a post request
        
        Arguments:
            raw_data {string} -- the json object of the decrypted post request dat
        
        Returns:
            string -- the decrypted user data
        """
        raw_data = json.loads(raw_data)
        user_data = self.hex_to_bytes(raw_data['user_data'])
        key_data = self.hex_to_bytes(raw_data['key_data'])
        key_data = self.decrypt_key_data(key_data)
        key, iv = self.extract_key_data_contents(key_data)
        contents = self.decrypt_contents(user_data, key, iv)
        return contents

    def process_chat_data(self, raw_data):
        """process the chat request
        
        Arguments:
            raw_data {string} -- the json object containing the chat request data
        
        Returns:
            (string, stirng, string) -- Returns a tuple containing the decrypted contents, the msg (for verification purposes), and the signaure
        """
        raw_data = json.loads(raw_data)
        contents = self.hex_to_bytes(raw_data['contents'])
        key_data = self.hex_to_bytes(raw_data['key_data'])
        signature = self.hex_to_bytes(raw_data['signature'])
        key_data = self.decrypt_key_data(key_data)
        key, iv = self.extract_key_data_contents(key_data)
        contents = self.decrypt_contents(contents, key, iv)
        msg = self.process_dict_for_encry(contents)
        return (contents, msg, signature)

    def create_chat_response(self, raw_data, pub_key):
        """Creats a chat response after a chat request. Creates a signature of the data to be sent using the server's private key
        
        Arguments:
            raw_data {string} -- json object for the data to be encrypted and sent back
            pub_key {byte} -- server's public key
        
        Returns:
            (string, string, string) -- returns a tuple of the ciphertext, the key data, and the signature of the signed message
        """
        raw_data = self.process_dict_for_encry(raw_data)
        ctxt, key, iv = self.encrypt_symmetric(raw_data)
        rsa = RSA.importKey(pub_key)
        rsa = PKCS1_OAEP.new(rsa)
        key_data = {"key": key, "iv": iv}
        key_data = self.process_dict_for_encry(key_data, encode=True)
        signature = self.sign_message(raw_data, self.get_server_priv_key())
        try:
            key_data = rsa.encrypt(key_data).hex()
            return (ctxt, key_data, signature)
        except Exception as e:
            print(e)

    def get_server_priv_key(self):
        with open("server_priv.PEM", 'r') as key_file:
            return key_file.read()

    def get_server_pub_key(self):
        with open("server_pub.PEM", 'r') as key_file:
            return key_file.read()


        