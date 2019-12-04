import os
from profile import Profile
from cryptochat import CryptoChat
from Crypto.PublicKey import RSA
import zmq
import sys
from time import sleep

def main_method():
    """Starts the cryptochat session
    """
    chat = CryptoChat()
    chat.start()

if __name__ == "__main__":
    main_method()

