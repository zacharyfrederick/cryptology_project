import zmq
import json
from encryption_manager import EncryptionManager
from time import sleep
import sys

class Messenger:
    """The messenger class responsible for creating and managing the ZMQ sockets
    """
    def __init__(self):
        """The constructor for the messenger. Creates the ZMQ context and creates the raw addresses used for connecting to
        or hosting a chat
        """
        self.context = zmq.Context()
        self.raw_addr = "tcp://{}:{}"
        self.server_addr = "tcp://*:{}"

    def wait_for_server_resp(self, priv_key,  port, pwd):
        """Called when a host is hosting a new chat and waiting for connection requests from the server
        
        Arguments:
            priv_key {bytes} -- The private key of this host
            port {[string]} -- [The port to accept connections over]
            pwd {[string]} -- The chat password for this chat
        
        Returns:
            [json] -- The decrypted contents of the incoming connection requests containing A's identity and key AB
        """
        try:
            encryption = EncryptionManager()
            socket = self.context.socket(zmq.REP)
            socket.bind(self.server_addr.format(port))
            print("Waiting for response from server...")

            while True:
                data = socket.recv().decode("utf-8")
                contents, msg, signature = encryption.process_chat_request_data(data, priv_key)
                s_pk = encryption.get_server_pub_key()

                if encryption.verify_message(msg, s_pk, signature) and contents['pwd'] == pwd:
                    print("Successfully recieved data from the server")
                    socket.send("success".encode())
                    return contents
                else:
                    socket.send("error".encode())
                    print("recieved invalid password. Exiting chat.")
                    break
        except Exception as e:
            print(e)

    def connect_to_host(self, ip, port, kab, iv, username):
        """Connects to a host over the specified ip, port. Encrypts and decrypts
        data using the specified key and iv. Once a connection is established stdin and the ZMQ socket
        are monitored for input. When stdin input is detected it is read, encrypted and sent over the socket. When
        the socket has incoming data it is read, decrypted, and printed to the screen. When an "exit()" message is recieved
        the host responds with a corresponding exit message and closes its connection  
        
        Arguments:
            ip {string} -- ip to connect to
            port {string} -- the port to connect through
            kab {byte} -- the symmetric key to use
            iv {byte} -- intialization vector
            username {stirng} -- the username of the other host to display
        """
        print("Attempting to connect to host")
        poller = zmq.Poller()
        encryption = EncryptionManager()
        iv = encryption.hex_to_bytes(iv)
        kab = encryption.hex_to_bytes(kab)
        addr = self.raw_addr.format(ip, port)
        socket = self.context.socket(zmq.PAIR)
        socket.connect(addr)

        poller.register(sys.stdin, zmq.POLLIN)
        poller.register(socket, zmq.POLLIN)

        sleep(1)
        success_msg = encryption.encrypt_symmetric_w_params("Connection established\n", kab, iv)
        socket.send_string(success_msg)

        while True:
            events = dict(poller.poll())
            stdin_ready = events.get(sys.stdin.fileno(), False)
            socket_ready = events.get(socket, False)
                
            if stdin_ready:
                test = sys.stdin.readline()
                if test == "exit()\n":
                        print("Exiting chat...")
                        ctxt = encryption.encrypt_symmetric_w_params(test, kab, iv)
                        socket.send_string(ctxt)
                        socket.close()
                        self.context.term()
                        break
                ctxt = encryption.encrypt_symmetric_w_params(test, kab, iv)
                socket.send_string(ctxt)
            elif socket_ready:
                data = socket.recv().decode("utf-8")
                data = encryption.hex_to_bytes(data)
                data = encryption.decrypt_symmetric_w_params(data, kab, iv).decode("utf-8")
                if data == "exit()\n":
                    print("Exiting chat...")
                    socket.close()
                    self.context.term()
                    break
                sys.stdout.write(username + ": " + data)

    def wait_for_host(self, port, kab, iv, username):
        """Waits for a host to connect over the specified port. Decrypts and ecrypts traffic using kab and iv. 
        Establishes a ZMQ socket and polls stdin and the socket for incoming data. When stdin input is detected it is read, 
        encrypted and sent over the socket. When the socket has incoming data it is read, decrypted, and printed to the screen.
        When an "exit()" message is recieved the host responds with a corresponding exit message and closes its connection  
        
        Arguments:
            port {string} -- the port to accept connections through
            kab {byte} -- the symmetric key to use
            iv {byte} -- initialization vector
            username {stirng} -- The username to display for the output messages
        """
        print("waiting for host to connect...")
        poller = zmq.Poller()
        encryption = EncryptionManager()
        kab = encryption.hex_to_bytes(kab)
        iv = encryption.hex_to_bytes(iv)
        try:
            socket = self.context.socket(zmq.PAIR)
            socket.bind(self.server_addr.format(port))
            poller.register(sys.stdin, zmq.POLLIN)
            poller.register(socket, zmq.POLLIN)

            sleep(1)
            success_msg = encryption.encrypt_symmetric_w_params("Connection established\n", kab, iv)
            socket.send_string(success_msg)
            while True:
                events = dict(poller.poll())
                stdin_ready = events.get(sys.stdin.fileno(), False)
                socket_ready = events.get(socket, False)

                if stdin_ready:
                    test = sys.stdin.readline()
                    if test == "exit()\n":
                        print("Exiting chat...")
                        ctxt = encryption.encrypt_symmetric_w_params(test, kab, iv)
                        socket.send_string(ctxt)
                        socket.close()
                        self.context.term()
                        break
                    ctxt = encryption.encrypt_symmetric_w_params(test, kab, iv)
                    socket.send_string(ctxt)
                elif socket_ready:
                    data = socket.recv().decode("utf-8")
                    data = encryption.hex_to_bytes(data)
                    data = encryption.decrypt_symmetric_w_params(data, kab, iv).decode("utf-8")
                    if data == "exit()\n":
                        print("Exiting chat...")
                        socket.close()
                        self.context.term()
                        break
                    sys.stdout.write(username + ": " + data)
                
        except Exception as e:
            print(e)

    

 
