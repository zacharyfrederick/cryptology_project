from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
import json
from Crypto.Signature import PKCS1_v1_5

class EncryptionManager:
    def __init__(self):
        pass

    def get_iv(self, hex=False):
        """Returns a random 16 byte initialization vector
        
        Keyword Arguments:
            hex {bool} -- [Return the IV in hex] (default: {False})
        
        Returns:
            [Initlization vector] -- [A 16-byte IV in the specified format]
        """     
        if hex:
            return get_random_bytes(16).hex()
        else:
            return get_random_bytes(16)

    def get_symmetric_key(self, hex=False):
        """Returns a random 32-byte symmetric key
        
        Keyword Arguments:
            hex {bool} -- [Return the key in hex] (default: {False})
        
        Returns:
            [key] -- [32 byte symmetric key in the specified format]
        """
        if hex:
            return get_random_bytes(32).hex()
        else:
            return get_random_bytes(32)

    def encrypt_symmetric(self, raw_data):
        """[Encrypt data symmetrically using a generated IV and key using AES]
        
        Arguments:
            raw_data {[String]} -- [the data to encrypt]
        
        Returns:
            [(ctx, key, iv)] -- [The ciphertext, key used, and IV all in hex]
        """
        iv = self.get_iv()
        key = self.get_symmetric_key()
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ctxt = cipher.encrypt(raw_data)
        return (ctxt.hex(), key.hex(), iv.hex())

    def create_encrypted_key_data(self, raw_data):
        """[Takes in data, encrypts it symmetrically, then encrypts the key data using the server's public key]
        
        Arguments:
            raw_data {[string]} -- [the data to encrypt]
        
        Returns:
            [(ctx key_data)] -- [The ciphertext and the encrypted key data]
        """
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
            
    def hex_to_bytes(self, data):
        """[Converts a hex value to its byte representation]
        
        Arguments:
            data {[String]} -- [The hex string to convert]
        
        Returns:
            [byte] -- [The converted data to byte format]
        """
        return bytes(bytearray.fromhex(data))

    def process_dict_for_encry(self, raw_data, encode=False):
        """[Takes in a dictionary and encodes it as json]
        
        Arguments:
            raw_data {[The data to encode]} -- [The dictionary to encode to json]
        
        Keyword Arguments:
            encode {bool} -- [Whether to return the data encoded as bytes] (default: {False})
        
        Returns:
            [json] -- [A json object in the specified format]
        """
        try:
            test = json.dumps(raw_data)
            if encode:
                return test.encode()
            else:
                return test
        except:
            print("Some error")

    def sign_message(self, msg, priv_key):
        """[Signs a message using a private key with PCS1_v1_5]
        
        Arguments:
            msg {[string]} -- [the message to sign]
            priv_key {[byte]} -- [the private key to sign with]
        
        Returns:
            [hex] -- [the signature encodes as hex]
        """
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
        """Takes in a message and signature and verifies the validity
        
        Arguments:
            msg {[string]} -- [the decrypted message]
            pub_key {[bytes]} -- [the public key to verify with]
            signature {[bytes]} -- [the unverified signature]
        
        Returns:
            [bool] -- [whether the verification was successful or not]
        """
        rsa = RSA.importKey(pub_key)
        h = SHA.new(msg.encode())
        verifier = PKCS1_v1_5.new(rsa)
        return verifier.verify(h, signature)

    def extract_key_data_contents(self, key_data):
        """Extracts the key data values
        
        Arguments:
            key_data {[json]} -- [The json object containing the key and iv]
        
        Returns:
            [(key, iv)] -- [The byte representation of the key and iv]
        """
        key = self.hex_to_bytes(key_data['key'])
        iv = self.hex_to_bytes(key_data['iv'])
        return (key, iv)

    def decrypt_contents(self, contents, key, iv):
        """[Decrypts the contents using the key and iv with AES] 
        
        Arguments:
            contents {bytes} -- The encrypted content
            key {byte} -- The symmetric key
            iv {byte} -- The initialization vector
        
        Returns:
            [json] -- [The decrypted contents in json format]
        """
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return json.loads(cipher.decrypt(contents).decode("utf-8"))

    def decrypt_key_data(self, priv_key, key_data):
        """Decrypts the key data using the private key and RSA
        
        Arguments:
            priv_key {byte} -- private key to decrypt with
            key_data {json} -- A json object with the key data in hex format
        
        Returns:
            string -- The plaintext encodes as utf-8
        """
        rsa = RSA.importKey(priv_key)
        rsa = PKCS1_OAEP.new(rsa)
        ptxt = json.loads(rsa.decrypt(key_data).decode("utf-8"))
        return ptxt

    def process_chat_request_data(self, raw_data, priv_key):
        """Takes in raw data from a chat request and decrypts it using the private key
        
        Arguments:
            raw_data {[json]} -- the raw post data in json format
            priv_key {byte} -- private key to decrypt with
        
        Returns:
            (contents, msg, signature) -- Returns the decrypted contents, the contents as json, and the signature of the chat request
        """
        raw_data = json.loads(raw_data)
        contents = self.hex_to_bytes(raw_data['contents'])
        key_data = self.hex_to_bytes(raw_data['key_data'])
        signature = self.hex_to_bytes(raw_data['signature'])
        key_data = self.decrypt_key_data(priv_key, key_data)
        key, iv = self.extract_key_data_contents(key_data)
        contents = self.decrypt_contents(contents, key, iv)
        msg = self.process_dict_for_encry(contents)
        return (contents, msg, signature)

    def get_server_pub_key(self):
        """Returns the server's public key
        
        Returns:
            bytes -- The public key as bytes
        """
        with open('server_pub.PEM', 'r') as key_file:
            return key_file.read()

    def encrypt_symmetric_w_params(self, data, key, iv):
        """Encrypts the data symmetrically using the key and iv with AES in CFB block mode
        
        Arguments:
            data {string} -- the data to encrypt
            key {byte} -- the key to encrypy with
            iv {byte} -- initialization vector
        
        Returns:
            ciphertext -- the ciphertext as hex
        """
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ctxt = cipher.encrypt(data)
        return (ctxt.hex())

    def decrypt_symmetric_w_params(self, data, key, iv):
        """Decrypts the data using the key and IV using AES and CFB block mode
        
        Arguments:
            data {byte} -- data in byte format
            key {byte} -- the key to decrypt
            iv {byte} -- Initialization vector
        
        Returns:
            [string] -- [plaintext]
        """
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ptxt = cipher.decrypt(data)
        return ptxt