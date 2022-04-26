'''
Author: Ben Ross
Date: 21/01/2022
Outline:
Holds the class for receiving messages from the server. It runs on it's own thread.
'''

# Python Imports
from socket import socket
from threading import Thread
import tkinter as tk
import pickle

# Local Imports
from Cryptography.AES import aesDecrypt

# Global Variables
RECV_BUFFER_SIZE: int = 1024


class Receiver(Thread):
    '''Listens for incoming messages from the server'''

    def __init__(self, sock, root: tk.Tk, client_connections: list) -> None:
        super().__init__(daemon=True)

        self.sock: socket = sock
        self.root: tk.Tk = root
        self.msg_queue: dict[str, list[bytes]] = {}
        self.client_connections = client_connections
        self.shared_key: bytes = b''

        self.running: bool = True

    def receiveData(self) -> tuple[str, bytes]:
        '''Uses the pickle module to deserialise the bytes
        sent by the server. The format is (sender, message)'''
        data_size: int = int.from_bytes(self.sock.recv(4), 'big') # get the size of the data
        if data_size == 0:
            return ('', b'')

        data_array: bytearray = bytearray()
        while len(data_array) < data_size:
            data_array += self.sock.recv(RECV_BUFFER_SIZE)

        data: bytes = bytes(data_array)

        if self.shared_key: # encrypt if the shared key has been established (after initECDHE_ECDSA)
            data = aesDecrypt(data, self.shared_key)
        return pickle.loads(data)


    def handleReceivedData(self, message: bytes, sender: str) -> bool:
        '''Handles the data received. Return false, f no data was received 
        (lost connection with the server), else true.'''
        if message == b'': # lost connection with server
            return False

        if sender in self.msg_queue:
            self.msg_queue[sender].append(message)
        else:
            self.msg_queue[sender] = [message]

        return True

    def run(self) -> None:
        '''Receives data from the server and displays it in the gui.'''
        sender: str
        message: bytes

        while self.running:
            sender, message = self.receiveData()

            if not self.handleReceivedData(message, sender):
                print('Oh No. We have lost connection to the server!')
                print('Quitting...')
                
                for connection in self.client_connections:
                    connection.send_kill_command = False
                    connection.killed_by_server = True
                    connection.killInstance()
                self.root.destroy() # kills the window
                return