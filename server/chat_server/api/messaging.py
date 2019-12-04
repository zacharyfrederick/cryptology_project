import zmq
import json

class Messenger:
    def __init__(self):
        self.context = zmq.Context()
        self.raw_addr = "tcp://{}:{}"

    def send_chat_request(self, ip, port, data):
        """Sends a chat request to the intended recipient through a ZMQ socket
            and waits for a reply from the host
        
        Arguments:
            ip {string} -- the destination ip
            port {string} -- the destination port
            data {string} -- json representation of the encrypted data
        
        Returns:
            [string] -- The status of the requested operations
        """
        addr = self.raw_addr.format(ip, port)
        socket = self.context.socket(zmq.REQ)
        print("Attempting to connect")
        socket.connect(addr)
        socket.send(data)
        data = socket.recv().decode("utf-8")
        if data == "success":
            print("Data successfully sent to host")
            return "success"
        elif data == "error":
            print("error contacting host")
            return "error"
