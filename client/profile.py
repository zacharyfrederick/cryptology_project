import json
import hashlib
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pbkdf2 import PBKDF2, crypt
import base64
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import requests

class Profile:
    """class that houses the profile data. Responsbile for creation loading and decryption"""
    class FileOutput:
        """A subclass that creates the file output. Used because the Profile data is serialized to json and we want this data saved separately"""
        def __init__(self, data, hashed_data, iv, salt):
            """Constructor. Takes in data, a has, iv, and salt
            
            Arguments:
                data {[type]} -- The data to save
                hashed_data {string} -- the hash of the data in hex
                iv {string} -- The hex of the iv
                salt {string} -- The hex of the salt value used 
            """
            self.data = data
            self.hashed_data = hashed_data
            self.iv = iv
            self.salt = salt
            
        def get_data(self):
            """Creates a json object of this objects data
            
            Returns:
                string -- json represenation of the data
            """
            return json.dumps(self.__dict__, indent=4)

    def __init__(self):
        pass

    def read_data(self, filename):
        """Reads the profile data from the specified filename
        
        Arguments:
            filename {string} -- filename of the profile data
        
        Returns:
            string -- plaintext of the decrypted profile data
        """
        with open(filename, 'r') as file:
            raw_data = json.loads(file.read())
            data, hashed_data, iv, salt = self.collect_json_values(raw_data) #collects the encrypted data, a hash of the data for verification, and the info needed to decrypt
            password = self.collect_passowrd() #collects the users password for decryption
            key = self.create_key(password, salt) #takes the password and the salt value and creates a key
            try:
                ptxt = self.decrypt_data(data, key, iv).decode("utf-8")
                unverified_hash = self.hash_data(ptxt)

                if unverified_hash == hashed_data: #verifies that the unencrypted data matches the hash
                    return ptxt
                else:
                    print("invalid password") #failed hash check means the data was unencrypted improperly 
                    return None
            except ValueError:
                print("Invalid password")
                return None
            

    def collect_json_values(self, raw_data):
        """Collects the data, hash, iv, and salt from the raw profile data
        
        Arguments:
            raw_data {json} -- json object of the raw profile data
        
        Returns:
            (string, byte, string, string) -- Returns the data object, the hash, the iv, and the salt
        """
        data = self.convert_from_hex(raw_data['data'])
        hashed_data = raw_data['hashed_data']
        iv = self.convert_from_hex(raw_data['iv'])
        salt = self.convert_from_hex(raw_data['salt'])
        return (data, hashed_data, iv, salt)

    def save_data(self, filename, key, salt):
        """Saves the profile data to the specified filename along with the salt value
        
        Arguments:
            filename {string} -- filename to output to
            key {byte} -- symmetric key to encrypt data with
            salt {byte} -- salt used with the passphrase
        """
        print("saving local profile")
        data = json.dumps(self.__dict__)
        iv = self.get_iv()
        hashed_data = self.hash_data(data)
        data = self.encrypt_data(data, key, iv).hex()
        file_output = self.FileOutput(data, hashed_data, iv.hex(), salt.hex()).get_data() #returns the final file output
        
        name = "{}.profile".format(filename)
        loc = os.path.join(os.getcwd(), "profiles", name)
        
        with open(loc, 'w') as file:
            file.write(file_output)

        print("profile saved as:", name)

    def create_key(self, password, salt):
        """Creates a symmetric key from a password, an 8-byte salt value using PBKDF2
        
        Arguments:
            password {string} -- passphrase for the user
            salt {byte} -- salt value
        
        Returns:
            byte -- 32 byte symmetric key
        """
        key = PBKDF2(password, salt).read(32)
        return key

    def hash_data(self, data):
        """Hashes the data using md5
        
        Arguments:
            data {string} -- data to be hased
        
        Returns:
            string -- hex value for the md5 hash of the data
        """
        return hashlib.md5(data.encode()).hexdigest()

    def convert_from_hex(self, value):
        """Converts a hex value to a byte value
        
        Arguments:
            value {string} -- hex value
        
        Returns:
            byte -- byte representation of the value
        """
        return bytes(bytearray.fromhex(value))

    def get_iv(self):
        """Returns a 16 byte random iv
        
        Returns:
            byte -- iv
        """
        return get_random_bytes(16)

    def decrypt_data(self, data, key, iv):
        """Decrypts the data using the specified key and iv using AES and CFB block mode
        
        Arguments:
            data {byte} -- encrypted data
            key {byte} -- key
            iv {byte} -- initialization vector
        
        Returns:
            byte -- plaintext of the encrypted data
        """
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(data)
    
    def encrypt_data(self, data, key, iv):
        """Encrypts the data using the key, iv and AES w/ CFB block mode
        
        Arguments:
            data {string} -- data to be encrypted
            key {byte} -- key to use
            iv {byte} -- initialization vector
        
        Returns:
            byte -- ciphertext of the data
        """
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.encrypt(data)

    def create_profile(self):
        """Starts the create a profile process
        """
        self.username = str(input("Enter a username: "))
        self.ip = str(input("Enter the ip address you want to accept connections over: "))
        self.port = str(input("Enter the port you want to use: "))
        salt, hpwd = self.create_password()
        self.generate_keys()
        self.save_data(self.username, hpwd, salt)
        self.register_w_server()

    def generate_keys(self):
        """Generates RSA keys and assigns them to current profile instance
        """
        print("generating rsa keys")
        rsa_key = RSA.generate(4096)
        self.pub_key = rsa_key.publickey().exportKey("PEM").decode("utf-8")
        self.private_key = rsa_key.exportKey('PEM').decode("utf-8")
    
    def create_password(self):
        """Collects a password from the user. Verifies it and creates a symmetric key from the passphrase
        
        Returns:
            (byte, byte) -- A tuple containing the salt used with the passphrase and the resulting symmetric key
        """
        while True:
            print("Enter a passphrase")
            password = getpass()
            print("Enter your passphrase again")
            password2 = getpass()

            if password == password2:
                salt, hashed = self.hash_password(password)
                return (salt, hashed)
            else:
                print("Passwords didn't match")

    def collect_passowrd(self):
        """Collects a password using the getpass() function so it doesnt show on the console
        
        Returns:
            string -- password
        """
        print("Enter your passphrase")
        password = getpass()
        return password

    def hash_password(self, password):
        """Hashes a password using an 8 byte salt
        
        Arguments:
            password {string} -- user's passphrase
        
        Returns:
            (byte, byte) -- a tuple containing the salt and the key
        """
        salt = get_random_bytes(8)
        key = PBKDF2(password, salt).read(32)
        return (salt, key)

    def register_w_server(self):
        """Registers the collect profile data with the server. Sends the identity of the profile encrypted symmetrically
        while the key data used is sent encrypted with the server's public key
        """
        print("registering with server")
        iv = self.get_iv()
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        raw_data = {"username": self.username, "pub_key": self.pub_key, "ip": self.ip, "port": self.port}
        raw_data = json.dumps(raw_data)
        encrypted_data = cipher.encrypt(raw_data).hex()

        with open("server_pub.PEM", 'r') as key_file:
            keys = {"key": key.hex(), "iv": iv.hex()}
            keys = json.dumps(keys).encode()
            key_encrypter = RSA.importKey(key_file.read())
            key_encrypter = PKCS1_OAEP.new(key_encrypter)
            encrypted_keys = key_encrypter.encrypt(keys).hex()

            data = json.dumps({"user_data": encrypted_data, "key_data": encrypted_keys})
        response = json.loads(requests.post("http://localhost:8000/api/v1/register", data=data).content)

        try:
            status = response['status']
            print("profile successfully created and registered")
        except:
            print(response)
            print("Error. Profile not registered with server. Exiting")
            exit(1)


