import os
from profile import Profile
import json
from encryption_manager import EncryptionManager
import requests
from messaging import Messenger
from subprocess import Popen
from Crypto.Random import get_random_bytes

class CryptoChat:
    """The main class that runs the progrm"""

    def __init__(self):
        """The constructor for crypto chat 
        """
        self.local_path = os.getcwd() #used for referencing the profile directory as well as the various key files
        self.files = [] #an intially empty list that holds the various profile files
        self.profile_selected = False #a flag that indicates if a valid profile has been chosen and the program can proceed
        self.valid_action_taken = False #Flag that indicates whether the user has selected a valid action such as load or create a profile
        self.delete_after_max_limit = True #a flag that indicates if you want to delete profiles after a set number of login attempts
        self.attempt_limit = 3 ##the max login attempt limit before a profile is deleted
        self.encryption = EncryptionManager() #the encryption manager that provides all encryption functionality

    def start(self):
        """Starts the program. Collects the profile files and determines the action to take
        """
        self.files = [] #resets the files variable incase program is restarted 
        self.get_files() #attempts to loads all of the profiles in the 'profile' directory
        self.determine_action() ##takes input from the user to determine what action to take

    def get_files(self):
        """Collects the profiles in the 'profile' directory. Exits the program if the dir does not exist
        """
        try:
            for file in os.listdir(os.path.join(self.local_path, "profiles")):
                if file.endswith(".profile"):
                    self.files.append(file)
        except FileNotFoundError:
            print("Error: Profiles directory not found. Exiting")
            exit(1)

    def determine_action(self):
        """Determines which action to take. Options are create or load a profile
        """
        while not self.valid_action_taken:
            action = str(input("Would you like to create (c) a profile or load a previous one (l): "))
            if action == "c":
                self.create_profile()
                self.get_files()
                self.load_profile()
            elif action == "l":
                self.load_profile()
            else:
                print("Invalid action requested")
        self.run_loop() #After a valid action has been taken this is the main loop of the program

    def create_profile(self):
        """method that creates a profile"""
        self.valid_action_taken = True
        self.profile = Profile() #creates an empty profile
        self.profile.create_profile() #requests user input to fill and save the profile
        
    def load_profile(self):
        """Starts the load profile process and monitors its stats
        """
        self.valid_action_taken = True
        while not self.profile_selected:
            self.select_profile()

    def select_profile(self):
        """Prints out the available profiles and prompts the user to pick one. Once selected it decrypts the profile and sets the profile data for this session
        If no profiles are found it starts the create a profile process
        """
        if len(self.files) > 0:
            print("Select an available profile to load: ")
            for index, file in enumerate(self.files):
                print("{}. {}".format(index + 1, file))

            try:
                selection = int(input("Enter a profile number to load: ")) - 1

                if selection < len(self.files) and selection >= 0:
                    self.profile_selected = True
                    print("{}. {} selected".format(
                        selection+1, self.files[selection]))

                    self.filename = os.path.join(self.local_path, "profiles", self.files[selection])
                    self.profile = Profile()
                    self.decrypt_profile()

            except ValueError as e:
                print("Error. Invalid Profile Selection")
        else:
            print("No profiles found.")
            print("Creating a profile now")
            self.create_profile()
            self.get_files()
            self.select_profile()

    def decrypt_profile(self):
        """This function is responsible for taking in the passphrase of the user in order
        to decrypt their profile. Deletes a profile after the max number of login attempts has been reached"""
        incorrect_attempts = 0
        profile_decrypted = False
        
        while not profile_decrypted:
            if incorrect_attempts == self.attempt_limit:
                if self.delete_after_max_limit:
                    print("Too many invalid attempts. Deleting profile")
                    os.remove(self.filename)
                else:
                    print("Too many invalid attempts. Exiting CryptoChat")
                exit(1)

            profile_data = self.profile.read_data(self.filename)
            if profile_data != None:
                profile_decrypted = True
                self.profile_data = json.loads(profile_data) #sets the current profile for this session
                print("Successfully signed in")
            else:
                incorrect_attempts +=1
            
    def run_loop(self):
        """The main loop of the program"""
        while True:
            print("Select an option:")
            print("1. Create a new chat") 
            print("2. Host a new chat")
            print("3. Exit")
            
            try:
                selection = int(input(">>> "))

                if selection == 1:
                    self.create_chat()
                elif selection == 2:
                    self.host_new_chat()
                elif selection == 3:
                    print("Thanks for using GatorChat")
                    break
                else:
                    print("Invalid Selection")
            except:
                print("Invalid Selection")
        exit(1)

    def create_chat(self):
        """This method attempts to establish a connection a host that is currently hosting a chat"""
        b_username = self.get_str_value("Enter the username of the recipient: ") #username for desired recipient 
        chat_pwd = self.get_str_value("Enter the chat password: ") #the chat password that B has selected
        self.key_ab = self.encryption.get_symmetric_key(hex=True) 
        self.iv = self.encryption.get_iv().hex()
        raw_data = {"a_username": self.profile_data['username'], "b_username": b_username, "pwd": chat_pwd, "kab": self.key_ab, 'iv': self.iv}
        ctxt, key_data = self.encryption.create_encrypted_key_data(raw_data) #encrypts the data and key data
        msg = self.encryption.process_dict_for_encry(raw_data)
        signature = self.encryption.sign_message(msg, self.profile_data['private_key']) #creates a signature based on the data
        post_data = self.encryption.process_dict_for_encry({"contents": ctxt, "key_data": key_data,  "signature": signature}) #creates the key data necessary to unencrypt
        try:
            response = requests.post("http://localhost:8000/api/v1/create_chat", data=post_data) #sends the server a post request to create a chat
            content = json.loads(response.content)
            print("content")
            status = content['status']
            print("Attempting to communicate with server...")
            
            messaging = Messenger()
            messaging.wait_for_host(self.profile_data['port'], self.key_ab,self.iv, b_username)
        except KeyError:
            print(content['error'])
        except requests.ConnectionError as e:
            print("Unable to communicate with server")
        except Exception as e:
            print(e)

    def get_str_value(self, prompt):
        """Gets a string value from the console using the specified prompt
        
        Arguments:
            prompt {string} -- the prompt to display
        
        Returns:
            stirng1 -- collected string
        """
        while True:
            try: 
                value = str((input(prompt)))
                return value
            except:
                print("Invalid value")

    def get_connection_info(self):
        """returns a tuple of the loaded profile data's connection info"""
        ip = self.profile_data['ip']
        port = self.profile_data['port']
        priv_key = self.profile_data['private_key']
        return (ip, port, priv_key)

    def host_new_chat(self):
        """Method to host a new chat. Takes in a desired password and waits for connections"""
        try:
            messenger = Messenger()
            pwd = self.get_str_value("Enter the password for this chat session: ")
            ip, port, priv_key = self.get_connection_info()
            contents = messenger.wait_for_server_resp(priv_key, port, pwd) #waits for the server to communicate that an incoming connection has been established
            messenger.connect_to_host(contents['a_ip'], contents['a_port'], contents['kab'], contents['iv'], contents['a_username']) #uses the data from the server to connect to the desired host
        except Exception as e:
            print(e)