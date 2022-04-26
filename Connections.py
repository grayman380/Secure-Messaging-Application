'''
Author: Ben Ross
Date: 20/01/22
Outline:
Holds classes related to managing the connection between a client and peer
Includes the Connection, Receive, and Peer classes.
'''

# Python Imports
from threading import Thread
from hashlib import pbkdf2_hmac
from os import path, system
import tkinter as tk
import socket, pickle

# Local Imports
from Receiver import Receiver
from Cryptography.AES import aesEncrypt
from Cryptography.EllipticCurves import EllipticCurve, EllipticCurveKeys
from Cryptography.SignalProtocol import DoubleRatchet
from Cryptography.Huffman import compress, decompress

# Global Variables
SERVER_UID: str = '0'*16
MAX_SEND_SIZE: int = 1024*1024*100 # 100 MB

class Peer():
    '''Essentially a wrapper for a uid'''
    def __init__(self, uid: str, nickname: str) -> None:
        self.uid: str = uid
        self.nickname: str = nickname if nickname else uid


class Connection():
    '''Management of client-server connection and integration of GUI'''

    def __init__(self, *args) -> None:
        self.uid: str = args[0]
        self.sock: socket.socket = args[1]
        self.receiver: Receiver = args[2]
        self.peer: Peer = args[3]
        self.root: tk.Tk = args[4]
        self.server_shared_key: bytes = args[5]
        self.ec: EllipticCurve = args[6]
        self.IK: EllipticCurveKeys = args[7]
        self.SPK: EllipticCurveKeys = args[8]
        self.OPKs: list[EllipticCurveKeys] = args[9]
        self.client_connections = args[10]
        self.client_connections.append(self)

        self.send_kill_command: bool = True
        self.killed_by_server: bool = False
        self.running: bool = True
        self.double_ratchet: DoubleRatchet
        self.use_double_ratchet: bool = False

        self.EKa: EllipticCurveKeys = self.ec.generateKeyPair()

        self.messages: tk.Listbox
        self.window: tk.Toplevel = self.buildGui()

        self.performX3DH()

        # Clear messages in cue if they exist (from previous connections to the peer)
        self.receiver.msg_queue[self.peer.uid] = []

        self.get_peer_messages_thread: Thread = Thread(target=self.getDataFromPeer)
        self.get_peer_messages_thread.start()

        self.root.wait_window(self.window)

        # if the window gets destroyed, kill the thread
        if not self.killed_by_server:
            self.killInstance()

    #####################################################################################
    # SENDING DATA METHODS
    def sendData(self, data: bytes, sender: str = '') -> None:
        '''Sends some data to the sender given (peer associated with this connection is default).
        Sends in the form of (recipient, message), serialised with pickle.'''
        e2e_encrypted_data: bytes = data
        if not sender: # default is self.peer.uid
            sender = self.peer.uid

            # Encrypt data with the double ratchet if it has been established, and the message
            if self.use_double_ratchet:
                e2e_encrypted_data = self.double_ratchet.ratchetEncrypt(data)
        
        # Pickle, and encrypt the data with the shared server key
        pickled_data: bytes = pickle.dumps((sender, e2e_encrypted_data))
        fully_encrypted_data: bytes = aesEncrypt(pickled_data, self.server_shared_key)

        # Check if the data size is too big
        if len(fully_encrypted_data) > MAX_SEND_SIZE:
            PopupWindow('Sending too much data. Cannot send more than 100 MB', self.root)
            return

        data_length: bytes = len(fully_encrypted_data).to_bytes(4, 'big')
        self.sock.sendall(data_length + fully_encrypted_data)

    def sendFile(self, filename: str) -> None:
        '''Sends a file instead of the raw text used to make the command.
        The file command is: <FILE> [file path]'''
        # Check if the given path exists, show alert if it isn't
        if not path.exists(filename):
            PopupWindow('The file path you entered was not valid.', self.root)
            return
        
        self.addMessageToBox(f"Sending file '{filename}'...", 'System'); self.window.update()
        shortened_filename: str = filename.split('/')[-1]
        filename_header: bytes = f'<STARTFILENAME>{shortened_filename}<ENDFILENAME>'.encode()

        with open(filename, 'rb') as file:
            self.sendData(filename_header + compress(file.read(), True))

        self.replaceLastLinesInWindow(f"Sending file '{filename}'... sent", 'System')

    def send(self, textInput: tk.Entry):
        '''Sends textInput data from the GUI'''
        message: str = textInput.get()
        textInput.delete(0, tk.END)

        # The case where it's a file being trasferred
        if message.startswith('<FILE>'):
            self.sendFile(message[7:])
        else:
            self.addMessageToBox(message, 'You')
            compressed_message: bytes = message.encode()
            self.sendData(compressed_message)
    
    #####################################################################################
    # RECEIVE DATA METHODS
    def addMessageToBox(self, message: str, sender: str) -> None:
        '''Adds a message to the gui box.'''
        if not self.window.winfo_exists():
            self.window.destroy()
            return
        self.messages.insert(tk.END, f'{sender}: {message}')

    def replaceLastLinesInWindow(self, *lines) -> None:
        if not self.root.winfo_exists() or not self.window.winfo_exists():
            self.window.destroy()
            return
        
        sender: str = lines[-1]
        lines = lines[:-1]

        for _ in range(len(lines)):
            self.messages.delete(tk.END)
        for line in lines:
            self.addMessageToBox(line, sender)


    def areMsgsWaitingFromSender(self, sender: str) -> bool:
        '''Returns whether or not there are any messages from the given
        sender in the queue.'''
        return bool(self.receiver.msg_queue.get(sender, False))

    def popMsgFromQueue(self, sender: str) -> bytes:
        '''Pops and returns the latest message from the specific sender
        from the msg queue shared between the client, all connections,
        and the receiver.'''
        return self.receiver.msg_queue[sender].pop(0)

    def receiveSaveAndOpenFile(self, file_data_with_header: bytes):
        '''Takes some file data and saves the file in the ReceivedFiles folder.'''
        filename_end_idx: int = file_data_with_header.index(b'<ENDFILENAME>')
        filename: str = file_data_with_header[15:filename_end_idx].decode()
        file_data: bytes = file_data_with_header[filename_end_idx+13:]
        
        self.addMessageToBox(f"Received '{filename}'. Saved in ReceivedFiles folder.", 'System'); self.window.update() # force the screen to show the message now

        with open(f'ReceivedFiles/{filename}', 'wb') as file:
            file.write(decompress(file_data))
        
        system(f'open ReceivedFiles/{filename}')


    def getDataFromPeer(self) -> None:
        '''Runs on it's own thread. Constantly queries the
        client's message queue (via the Receive object).'''
        while self.receiver.running and self.running:
            if not self.areMsgsWaitingFromSender(self.peer.uid):
                continue
        
            # Get and decrypt data
            encrypted_message: bytes = self.popMsgFromQueue(self.peer.uid)
            decrypted_message: bytes = self.double_ratchet.ratchetDecrypt(encrypted_message)
            
            if decrypted_message == b'KILLCONNECTION': # Check if kill command as been sent
                self.send_kill_command = False
                self.window.destroy()
            elif decrypted_message.startswith(b'<STARTFILENAME>'): # check if a file was sent
                self.receiveSaveAndOpenFile(decrypted_message)
            else:
                # Decompress and add message to display box
                self.addMessageToBox(decrypted_message.decode(), self.peer.nickname)

    #####################################################################################
    # EXTENDED TRIPLE DIFFIE-HELLMAN METHODS
    def performX3DH(self) -> None:
        '''Performs the Extended Triple Diffie-Hellman (3XDH):
        Only gets messages that are marked with b'3XDH' which signifies the message
        contains the prekey bundle or initial message of the peer.'''
        # Check if the user has already received a message from the peer,
        # indicating that this user is playing the role of Bob
        if not self.areMsgsWaitingFromSender(self.peer.uid):
            # This user is alice, so request the server gives you bob's prekey bundle
            pickled_data: bytes = pickle.dumps({'cmd': 'EstablishConnection', 'peer_uid': self.peer.uid})
            self.sendData(pickled_data, SERVER_UID)

        # This is Bob
        while self.receiver.running and self.running: # run until it finds a valid message
            for uid in self.receiver.msg_queue: # loop through uid's with messages outstanding
                for message in self.receiver.msg_queue[uid][::-1]: # loop through outstanding messagings from a uid (backwards so removal doesn't fuck anything up)
                        
                    if message.startswith(b'X3DH'): # if the message is a X3DH instruction
                        if uid == SERVER_UID: # this user is alice, getting bob's prekey bundle from the server
                            self.aliceX3DH(message[4:])
                        else: # this user is bob, getting alice's prekey bundle and init message from alice
                            self.bobX3DH(message[4:])

                        self.receiver.msg_queue[uid].remove(message) # remove message
                        return
        print('finished X3DH')

    def aliceX3DH(self, data: bytes) -> None:
        '''This function follows the steps that Alice takes during the X3DH algorithm.'''
        bob_prekey_bundle: dict = pickle.loads(data)

        # Split bob's prekey bundle into the relevant data
        IPKb: tuple[int, int] = self.ec.decompressPoint(bob_prekey_bundle['IPK'])
        SPKb: tuple[int, int] = self.ec.decompressPoint(bob_prekey_bundle['SPK'])
        signature: bytes = bob_prekey_bundle['signature']

        # Verify signature
        if not self.ec.verify(signature, bob_prekey_bundle['SPK'], IPKb):
            raise Exception('Requested user\'s signature is invalid')

        # Perform the Diffie-Hellman exchanges and combine them
        DH1: bytes = self.ec.encodePoint(self.ec.multiply(self.IK.private, SPKb))
        DH2: bytes = self.ec.encodePoint(self.ec.multiply(self.EKa.private, IPKb))
        DH3: bytes = self.ec.encodePoint(self.ec.multiply(self.EKa.private, SPKb))
        DHs: bytes = DH1 + DH2 + DH3

        # Handle the case that a one-time key was also transmitted
        OPK_exists: bool = 'OPK' in bob_prekey_bundle
        public_OPKb: tuple[int, int] = (0, 0) # default
        if OPK_exists: # if an OPK was given
            public_OPKb: tuple[int, int] = bob_prekey_bundle['OPK']
            DHs += self.ec.encodePoint(self.ec.multiply(self.EKa.private, public_OPKb))

        # Produce the shared secret, build the double ratchet and encrypt the initial message
        shared_secret = pbkdf2_hmac('sha3_512', DHs, b'', 10000, 32)
        self.double_ratchet = DoubleRatchet(self.ec, shared_secret, IPKb)
        ciphertext: bytes = self.double_ratchet.ratchetEncrypt(f'{self.uid} is requesting to chat'.encode())

        # Accumulate and pickle initial message, then send the data to bob
        data_dict: dict[str, tuple[int, int] | bytes] = {'IPKa': self.IK.public, 'EPKa': self.EKa.public, 'ciphertext': ciphertext}
        if OPK_exists: data_dict['OPKb'] = public_OPKb
        self.sendData(b'X3DH' + pickle.dumps(data_dict))

        self.addMessageToBox(f'Waiting for {self.peer.nickname} to request to chat with you', 'System')
        self.use_double_ratchet = True

    def bobX3DH(self, data: bytes) -> None:
        '''This function follows the steps that Bob takes during the X3DH algorithm.
        initial_message = comp_public_IKa | comp_public_EKa | comp_public_OPKib | ciphertext'''
        initial_message: dict = pickle.loads(data)

        # Split Alice's prekey message into the relevant data
        IPKa: tuple[int, int] = initial_message['IPKa']
        EPKa: tuple[int, int] = initial_message['EPKa']
        ciphertext: bytes = initial_message['ciphertext']

        # Perform the Diffie-Hellman exchanges and combine them
        DH1: bytes = self.ec.encodePoint(self.ec.multiply(self.SPK.private, IPKa))
        DH2: bytes = self.ec.encodePoint(self.ec.multiply(self.IK.private, EPKa))
        DH3: bytes = self.ec.encodePoint(self.ec.multiply(self.SPK.private, EPKa))
        DHs: bytes = DH1 + DH2 + DH3
        
        # Test if OPK was used and find the private component relating to the compressed public
        if 'OPKb' in initial_message:
            for key in self.OPKs:
                if key.public == initial_message['OPKb']:
                    DHs += self.ec.encodePoint(self.ec.multiply(key.private, EPKa))

        # Produce sharered secret, build double ratchet and decrypt initial message
        shared_secret = pbkdf2_hmac('sha3_512', DHs, b'', 10000, 32)
        self.double_ratchet = DoubleRatchet(self.ec, shared_secret, self.IK)
        plaintext: bytes = self.double_ratchet.ratchetDecrypt(ciphertext)

        self.addMessageToBox(plaintext.decode(), 'System')
        self.use_double_ratchet = True

    #####################################################################################
    # MISCELLANEOUS METHODS
    def killInstance(self):
        if self.send_kill_command:
            self.sendData(b'KILLCONNECTION')
        elif not self.killed_by_server:
            PopupWindow(f'{self.peer.nickname} has closed the connection.', self.root)

        self.running = False
        if self in self.client_connections:      # sometimes self isn't in the list. No idea why.
            self.client_connections.remove(self) # Doing this means no matter what, the connection is removed

    def buildGui(self) -> tk.Toplevel:
        '''Builds the gui for a new window'''
        window: tk.Toplevel = tk.Toplevel(self.root)
        window.title(self.peer.nickname)
        
        fromMessage = tk.Frame(master=window)
        scrollBar = tk.Scrollbar(master=fromMessage)
        messages = tk.Listbox(master=fromMessage, yscrollcommand=scrollBar.set)
        scrollBar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
        messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.messages = messages

        fromMessage.grid(row=0, column=0, columnspan=2, sticky='nsew')
        fromEntry: tk.Frame = tk.Frame(master=window)
        textInput: tk.Entry = tk.Entry(master=fromEntry)

        textInput.pack(fill=tk.BOTH, expand=True)
        textInput.bind('<Return>', lambda _: self.send(textInput))

        btnSend: tk.Button = tk.Button(
            master=window,
            text='Send',
            command=lambda: self.send(textInput)
        )

        fromEntry.grid(row=1, column=0, padx=10, sticky='ew')
        btnSend.grid(row=1, column=1, padx=10, sticky='ew')

        window.rowconfigure(0, minsize=800, weight=1)
        window.rowconfigure(1, minsize=50, weight=0)
        window.columnconfigure(0, minsize=300, weight=1)
        window.columnconfigure(1, minsize=200, weight=0)

        return window



class PopupWindow():
    '''Creates a window that pops up to give
    a message to the user'''

    def __init__(self, message: str, root: tk.Tk) -> None:
        window: tk.Toplevel = self.buildGui(message, root)
        window.mainloop()

    def buildGui(self, message: str, root: tk.Tk) -> tk.Toplevel:
        '''Builds the gui for a new window'''

        pop: tk.Toplevel = tk.Toplevel(root)
        pop.title('Alert')
        x: int = max(len(message)*10, 200)
        pop.geometry(f'{x}x150')

        pop_label: tk.Label = tk.Label(pop, text=message, font=('Calbri', 18, 'bold'))
        pop_label.pack(pady=20)

        frame: tk.Frame = tk.Frame(pop)
        frame.pack(pady=10)

        button: tk.Button = tk.Button(frame, text='Ok', bg='blue',
                                     command=lambda: pop.destroy())
        button.grid()

        return pop