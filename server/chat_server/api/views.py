from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from Crypto.PublicKey import RSA
import os
from Crypto.Cipher import PKCS1_OAEP
import json
from Crypto.Cipher import AES
from .models import Profile
from django.http import JsonResponse
from .encryption_manager import EncryptionManager
from .messaging import Messenger

# Create your views here.
class RegisterView(APIView):
    """The view that is called when a user posts to /api/v1/resgister"""
    def post(self, request, *args, **kwargs):
        """The handler for the post requests. Creates a new profile if data is correct and user with a certain username doesnt
        already exist
        
        Arguments:
            request {Request} -- Request object
        
        Returns:
            JsonResponse -- A json object containing the status of the the requested operation
        """
        encryption = EncryptionManager()
        contents = encryption.process_register_data(request.body)
        username, pub_key, ip, port = encryption.extract_user_data(contents)
            
        if not Profile.objects.filter(username=username).exists():
            try:
                profile = Profile(username=username, pub_key = pub_key, ip = ip, port =port)
                profile.save()
            except:
                return JsonResponse({"error": "Profile not created"})
        else:
            return JsonResponse({"error": "username already exists"})
        return JsonResponse({"status": "success"})

class StartChatView(APIView):
    def post(self, request, *args, **kwargs):
        """The handler for when a user attempts to start a chat through the api. 
        If the decryption is successful and the signature matches the user who sent it the data is 
        passed to the intended recipient specified by the username sent by the first host
        
        Arguments:
            request {Request} -- the request object
        
        Returns:
            JsonResponse -- The json response for the status of the requested operation
        """
        encryption = EncryptionManager()
        contents, msg, signature = encryption.process_chat_data(request.body)
        print(contents)
        a_username, kab, pwd, iv = self.extract_contents(contents)
        try:
            a_pk, a_ip, a_port = self.get_connection_info(username=a_username)

            if encryption.verify_message(msg, a_pk, signature):
                b_pk, b_ip, b_port = self.get_connection_info(username=contents['b_username'])
                raw_data = {"a_username": a_username, "a_ip": a_ip, "a_port": a_port, "kab": kab, "pwd": pwd, "iv": iv}
                ctxt, key_data, signature = encryption.create_chat_response(raw_data, b_pk)
                msg_data = {"contents": ctxt, "key_data": key_data, "signature": signature}
                msg_data = encryption.process_dict_for_encry(msg_data, encode=True)
                messenger = Messenger()
                result = messenger.send_chat_request(b_ip, b_port, msg_data)
                
                if result == "success":
                    return JsonResponse({"status": "success"})
                elif result == "error":
                    return JsonResponse({"error": "Invalid passowrd"})
            else:
                return JsonResponse({"error": "invalid signature"})
            return JsonResponse({"status": "success"})
        except Exception as e:
            print(e)
            return JsonResponse({"error": "you are not a registered user"})

    def get_connection_info(self, username):
        """Gets the connection info for a profile with the specified username
        
        Arguments:
            username {string} -- the profile's username
        
        Returns:
            (string, string, string) -- A tuple containing the profiles public key, ip, and port
        """
        profile = Profile.objects.get(username=username)
        return (profile.pub_key, profile.ip, profile.port)

    def extract_contents(self, contents):
        """Extrats the key, password, and iv from the contents
        
        Arguments:
            contents {json} -- json object containing the data
        
        Returns:
            (stirng, string, string, stirng) -- Returns the sender's username, the specified symmetric key, the password, and the iv
        """
        a_username = contents['a_username']
        kab = contents['kab']
        pwd = contents['pwd']
        iv = contents['iv']
        return (a_username, kab, pwd, iv)

    def get_server_priv_key(self):
        """Reads the server's private key
        
        Returns:
            byte -- the server's private key
        """
        with open("server_priv.PEM", 'r') as key_file:
            return key_file.read()

    def get_server_pub_key(self):
        """Returns the server's public key
        
        Returns:
            byte -- the server's public key
        """
        with open("server_pub.PEM", 'r') as key_file:
            return key_file.read()