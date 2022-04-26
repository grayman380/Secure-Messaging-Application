'''
Author: Ben Ross
Date: 25/12/21
Outline:
This file holds all of the logic for running the client's
side of the application.
'''

# Python Imports
from hashlib import pbkdf2_hmac
from secrets import token_bytes
from argparse import ArgumentParser
from string import ascii_lowercase, digits
from sys import exit
import tkinter as tk
import socket, pickle, json

# Local Imports
from Connections import Connection, Peer, PopupWindow
from Receiver import Receiver
from Cryptography.AES import aesEncrypt
from Cryptography.EllipticCurves import EllipticCurve, EllipticCurveKeys
from Cryptography.HelpfulFunctions import intToBytes

# Global Variables
CHARACTER_SET: set[str] = set(ascii_lowercase + digits)
SERVER_UID: str = '0'*16
NO_OF_OKs: int = 20



class Client():
    '''The main class for a client. Allows a user to login to the messaging application and
    open connections with other users.'''

    #####################################################################################
    # ADMINISTRATIVE METHODS
    def __init__(self, host: str, port: int, curve_name: str) -> None:
        self.host: str = host
        self.port: int = port
        self.curve_name = curve_name

        self.text_entry_mode: str = 'login or register' # abbreviated description of what stage the user is in
        self.is_root_dead: bool = False

        self.uid: str = ''
        self.connections: list[Connection] = []
        self.shared_key: bytes = b''
        self.registered_this_session: bool


    def main(self) -> None:
        '''Makes a connection to the server, gets the name, and sets up a receiver'''
        self.root: tk.Tk = self.buildMainWindow()        
        
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.messages.insert(tk.END, f'Trying to connect to {self.host} : {self.port}...')

        try:
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print('Connection Refused.')
            exit()
        
        # Display messages on the 
        self.appendLineInWindow(f'Successfully conected to {self.host} : {self.port}' + '\n')
        self.appendLineInWindow('Unique IDs must be 16 lowercase letters or numbers.' + '\n')

        # Create and start recieve thread
        self.receiver: Receiver = Receiver(self.sock, self.root, self.connections)
        self.receiver.start()
        self.msg_queue: dict[str, list[bytes]] = self.receiver.msg_queue

        # Perform the initial Diffie-Hellman exchange
        self.initialECDHE_ECDSA()
        self.receiver.shared_key = self.shared_key

        self.appendLineInWindow("Enter 'l' to login or 'r' to register:") # first prompt

        self.root.mainloop()

        # Only runs once the main window is destroyed
        self.is_root_dead = True
        self.receiver.running = False # stop the receive thread

    def buildMainWindow(self) -> tk.Tk:
        '''Builds and returns the main window'''
        root: tk.Tk = tk.Tk()
        root.title('Chat App')
        
        font = ('Arial', 18, 'bold')

        fromMessage = tk.Frame(master=root)
        scrollBar = tk.Scrollbar(master=fromMessage)
        messages = tk.Listbox(master=fromMessage, yscrollcommand=scrollBar.set, font=font)
        scrollBar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
        messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.messages = messages

        fromMessage.grid(row=0, column=0, columnspan=2, sticky='nsew')
        fromEntry: tk.Frame = tk.Frame(master=root)
        textInput: tk.Entry = tk.Entry(master=fromEntry, font=font)

        textInput.pack(fill=tk.BOTH, expand=True)
        textInput.bind('<Return>', lambda _: self.enterText(textInput))
        textInput.bind('<Meta_L><BackSpace>', lambda _: textInput.delete(0, tk.END))

        btnSend: tk.Button = tk.Button(
            master=root,
            text='Enter',
            command=lambda: self.enterText(textInput)
        )

        fromEntry.grid(row=1, column=0, padx=10, sticky='ew')
        btnSend.grid(row=1, column=1, padx=10, sticky='ew')

        root.rowconfigure(0, minsize=500, weight=1)
        root.rowconfigure(1, minsize=50, weight=0)
        root.columnconfigure(0, minsize=500, weight=1)
        root.columnconfigure(1, minsize=200, weight=0)

        return root


    def isUIDInvalid(self, uid: str) -> str:
        '''Checks if the given string uid is valid. Returns an empty string if it
        is, and an error message if it isn't'''
        if len(uid) != 16:
            to_return: str = str(abs(len(uid) - 16)) + ' character(s) too '
            return to_return + 'short' if len(uid) < 16 else to_return + 'long'

        invalid_chars: list[str] = [char for char in uid if char not in CHARACTER_SET]
        if invalid_chars:
            return "'" + "' '".join(invalid_chars) + "' are not valid"

        if self.uid and self.uid == uid: # check to see if you're requesting your own uid
            return 'Cannot enter your own unique ID'

        return '' # valid

    def appendLineInWindow(self, line: str = '') -> None:
        lines: list[str] = line.split('\n')
        for line in lines:
            self.messages.insert(tk.END, line)

    def replaceLastLinesInWindow(self, *lines) -> None:
        if self.is_root_dead:
            return

        for _ in range(len(lines)):
            self.messages.delete(tk.END)
        for line in lines:
            self.messages.insert(tk.END, line)

    def sendDataToServer(self, data: bytes) -> None:
        '''Sends data to the server for control and setup purposes.
        Sends in the form of (recipient, message), serialised with pickle.'''
        pickled_data: bytes = pickle.dumps((SERVER_UID, data))
        encrypted_data: bytes = aesEncrypt(pickled_data, self.shared_key) if self.shared_key else pickled_data 

        data_length: bytes = len(encrypted_data).to_bytes(4, 'big')
        self.sock.sendall(data_length + encrypted_data)

    def areMsgsWaitingFromServer(self, sender: str = SERVER_UID) -> bool:
        '''Returns whether or not there are any messages from the given
        sender in the queue.'''
        return bool(self.msg_queue.get(sender, False))

    def popMsgFromQueue(self, sender: str = SERVER_UID) -> bytes:
        '''Pops and returns the latest message from the specific sender
        from the msg queue shared between the client, all connections,
        and the receiver.'''
        return self.msg_queue[sender].pop(0)

    def getDataFromServer(self, display_data: bool = True) -> bytes:
        '''Runs until the server sends a message'''
        while self.receiver.running:
            if self.areMsgsWaitingFromServer():
                message: bytes = self.popMsgFromQueue()
                if display_data:
                    self.appendLineInWindow(message.decode())
                return message
        return b''


    #####################################################################################
    # TEXT ENTRY METHODS
    def loginOrRegisterMode(self, data: str) -> None:
        '''Method for the 'login or register' mode'''
        if not data: # skip if nothing was entered
            return

        if data.lower() not in ['l', 'r']: # not valid
            PopupWindow("You did not enter 'l' or 'r'. Try Again.", self.root)
            return

        self.replaceLastLinesInWindow(f"Enter 'l' to login or 'r' to register: {data}")
        data = data.lower()
        
        if data == 'l': # user chose to login
            self.appendLineInWindow('Enter your unique ID to login:')
            self.text_entry_mode = 'get uid to login' # update mode
        else: # user chose to register
            self.requestUIDToRegister()       

    def requestUIDToRegister(self) -> None:
        '''Requests that the server returns a uid that has not been
        previously registered. This becomes the user's uid'''
        self.sendDataToServer(pickle.dumps({'cmd': 'RegisterUID'}))
        
        self.uid = self.getDataFromServer(False).decode() # get the next message from the server (should be only one).
        self.appendLineInWindow(f'Your generated unique ID: {self.uid}')
        self.appendLineInWindow('Enter a password:')
        self.text_entry_mode = 'get password to register' # update mode

    def getPasswordToRegisterMode(self, data: str) -> None:
        '''Method for 'get password to register' mode'''
        if not data: # TODO: make a stricter requirement for a password
            # self.replaceLastLinesInWindow('Invalid Password: Try Again:')
            pass

        self.replaceLastLinesInWindow(f'Enter a password: {"*"*len(data)}')
        self.appendLineInWindow('Registering...')
        self.root.update() # refresh the window

        # Generate and save IK
        key_dict: dict[str, dict[str, int]] = EllipticCurve.generateKeysForAllCurves()
        with open(f'IdentityKeys/{self.uid}_IKs.json', 'w') as file:
            json.dump(key_dict, file)

        # Salt and hash password, get compressed public keys
        salt: bytes = token_bytes(16)
        hashed_password: bytes = pbkdf2_hmac('sha3_512', data.encode(), salt, 100000)
        public_IKs: dict[str, bytes] = {size: intToBytes(keys['CompressedPublic']) for size, keys in key_dict.items()}
        
        # Accumulate and pickle data for sending, then send
        data_dict: dict = {
            'cmd': 'RegisterPassword', 'salt': salt, 'hashed_password': hashed_password,
            'public_IKs': public_IKs
        }
        self.sendDataToServer(pickle.dumps(data_dict))

        response: str = self.getDataFromServer(False).decode()

        if response == 'Registration Successful':
            self.registered_this_session = True
            self.generateAndSendPrekeysToServer()

            self.replaceLastLinesInWindow('Registration Successful')
            self.appendLineInWindow('\n' + '#'*50 + '\n')
            self.appendLineInWindow('Enter the unique ID of the person you wish to talk to:')
            self.text_entry_mode = 'get uid of peer' # update mode to fully logged in
        else:
            PopupWindow(response, self.root)

    def getUIDToLoginMode(self, data: str) -> None:
        '''Method for 'get uid to login' mode'''
        if (error := self.isUIDInvalid(data)):
            # self.replaceLastLinesInWindow(f'Invalid unique ID. ' + error + '. Try Again:')
            PopupWindow(f'Invalid unique ID. ' + error + '. Try Again', self.root)
        else:
            self.uid = data # save uid

            # Accumulate and pickle data, then send
            pickled_data: bytes = pickle.dumps({'cmd': 'LoginUID', 'uid': self.uid}) # tell the server the uid the user is trying to log in as
            self.sendDataToServer(pickled_data) 

            self.replaceLastLinesInWindow(f'Enter your unique ID to login: {data}')
            self.appendLineInWindow('Enter your password:')

            self.text_entry_mode = 'get password to login' # update mode

    def getPasswordToLoginMode(self, data: str) -> None:
        '''Method for 'get password to login' mode'''
        if not data: # if nothing was entered, do nothing
            return

        self.replaceLastLinesInWindow(f'Enter your password: {"*"*len(data)}')
        self.appendLineInWindow('Logging In...')
        self.root.update() # refresh the window

        # Accumulate and pickle data, then send
        pickled_data: bytes = pickle.dumps({'cmd': 'LoginPassword', 'password': data})
        self.sendDataToServer(pickled_data)

        response: str = self.getDataFromServer(False).decode()
    
        if response == 'Login Successful':
            self.registered_this_session = False
            self.generateAndSendPrekeysToServer()

            self.replaceLastLinesInWindow(response)
            self.appendLineInWindow('\n' + '#'*50 + '\n')
            self.appendLineInWindow('Enter the unique ID of the person you wish to talk to:')
            self.text_entry_mode = 'get uid of peer' # update mode to fully logged in
        else:
            self.replaceLastLinesInWindow(f'Enter your password: ')
            PopupWindow(response, self.root) # error


    def getUIDOfPeerMode(self, data: str) -> None:
        '''Gets the uid of a user this user wants to talk to'''
        if (error := self.isUIDInvalid(data)): # if invalid id
            # self.replaceLastLinesInWindow(f'Invalid unique ID. ' + error + '. Try Again:')
            PopupWindow(f'Invalid unique ID. ' + error + '. Try Again. ', self.root)
            return

        # Query the server to see if the user is online
        # Accumulate and pickle data, then send
        pickled_data: bytes = pickle.dumps({'cmd': 'QueryUID', 'uid': data})
        self.sendDataToServer(pickled_data)

        response: str = self.getDataFromServer(False).decode()

        if response == 'online':
            self.replaceLastLinesInWindow(f'Enter the unique ID of the person you wish to talk to: {data}')
            self.peer_being_built_uid = data # save info so Peer object can be created at the next step

            self.appendLineInWindow('Enter a nickname for this unique ID. Or just hit enter again to skip:') # Next prompt
            self.text_entry_mode = 'nickname for peer' # update mode
        else: # response == 'offline'
            PopupWindow('User is not currently active or hasn\'t been registered. Wait or enter a different unique ID.', self.root)

    def getNicknameOfPeerMode(self, data: str) -> None:
        '''Gets a nickname of a user that this user wants to talk to,
        but this is optional.'''
        # Fill in previous message with input
        self.replaceLastLinesInWindow(f'Enter a nickname for this unique ID. Or just hit enter again to skip: {data}')

        # Setup for the next mode
        self.appendLineInWindow('User has been requested. A new window has opened for the chat.')
        self.appendLineInWindow('\n' + '#'*50 + '\n')
        self.appendLineInWindow('Enter the unique ID of the person you wish to talk to:') # Next prompts

        self.root.update() # update screen

        self.text_entry_mode = 'get uid of peer' # move back to get a new uid

        # Create new Peer and Connection object with the given information
        peer: Peer = Peer(self.peer_being_built_uid, data)
        Connection(
            self.uid, self.sock, self.receiver, peer, self.root, 
            self.shared_key, self.ec, self.IK, self.SPK, self.OKs, self.connections
        )


    def enterText(self, textInput: tk.Entry) -> None:
        '''Processes text entered in the text box.
        Could either ask for your name (only happens once),
        or it asks for names to talk to'''

        data: str = textInput.get()
        textInput.delete(0, tk.END)

        # Go to relevant method, corresponding to the current mode
        match self.text_entry_mode:
            case 'login or register': # asked user to login or register
                self.loginOrRegisterMode(data)
            case 'get uid to login': # asked user to enter uid for login
                self.getUIDToLoginMode(data)
            case 'get password to login': # asked user to enter password 
                self.getPasswordToLoginMode(data)
            case 'get password to register': # asked user to enter a password
                self.getPasswordToRegisterMode(data)
            case 'get uid of peer': # Get the uid the person has entered, ensuring it's valid
                self.getUIDOfPeerMode(data)
            case 'nickname for peer': # Get the nickname the person has entered. Accept an empty string to mean no nickname required
                self.getNicknameOfPeerMode(data)
            case _:
                raise ValueError('Invalid text_entry_mode')
   
    #####################################################################################
    # ENCRPYTION METHODS
    def initialECDHE_ECDSA(self):
        '''Ephemeral ECDH signed with ECDSA with the server'''
        # Choose curve parameter and create ec object
        self.ec: EllipticCurve = EllipticCurve(self.curve_name)
        
        # Generate random integer and point on curve
        ephemeral_keys: EllipticCurveKeys = self.ec.generateKeyPair()
        
        # Accumulate and pickle the curve name and ephemeral public key, then send
        pickled_data: bytes = pickle.dumps({
                                'cmd': 'InitDiffieHellman', 'curve_name': self.curve_name, 
                                'client_ephemeral_public': ephemeral_keys.public})
        self.sendDataToServer(pickled_data)

        # Unload the server's response into the relevant data
        data_dict: dict = pickle.loads(self.getDataFromServer(False))
        public_IKs: tuple[int, int] = data_dict['public_IKs']
        public_EKs: tuple[int, int] = data_dict['public_EKs']
        document: bytes = data_dict['document']
        signature: bytes = data_dict['signature']

        # Verify signature
        is_signature_valid: bool = self.ec.verify(signature, document, public_IKs)
        if not is_signature_valid:
            raise Exception('Invalid Signature')

        # Perform Diffie-Hellman and generate shared secret
        dh_output: bytes = self.ec.encodePoint(self.ec.multiply(ephemeral_keys.private, public_EKs))
        self.shared_key: bytes = pbkdf2_hmac('sha3_256', dh_output, bytes(16), 100000) # 256 bit key


    def generateAndSendPrekeysToServer(self):
        '''Generates and sends the user's IK (Identity Public Key), SPK (Signed Prekey Key),
        Sig (Prekey signature), and OPKs (One-time prekeys). Only generates IK if the
        user has registered this session.
        '''
        # Load IK from file
        with open(f'IdentityKeys/{self.uid}_IKs.json', 'r') as file:
            key_from_file = json.load(file)[self.curve_name]
        self.IK: EllipticCurveKeys = EllipticCurveKeys(key_from_file['CompressedPublic'],
                                                        key_from_file['Private'], self.ec)

        # Generat the rest of the prekeys
        self.SPK: EllipticCurveKeys = self.ec.generateKeyPair()
        self.Sig: bytes = self.ec.sign(self.SPK.compPublicKeyAsBytes(), self.IK.private)
        self.OKs = [self.ec.generateKeyPair() for _ in range(NO_OF_OKs)]

        # Accumulate and pickle the prekey bundle, then send
        data_dict: dict[str, str | bytes | list[tuple[int, int]]] = {
            'cmd': 'SharePrekeyBundle', 'encoded_SPK': self.ec.encodePoint(self.SPK.public),
            'signature': self.Sig, 'OPKs': [OK.public for OK in self.OKs]
        }
        self.sendDataToServer(pickle.dumps(data_dict))



if __name__ == '__main__':
    from os import system; system('clear')

    parser: ArgumentParser = ArgumentParser(description='Messaging Application: Client')
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=6174, help='TCP port (defualt 6174)')
    parser.add_argument('-c', metavar='CURVE', type=str, default='P-521', help='Curve Parameter (default P-521)')

    args = parser.parse_args()

    client: Client = Client(args.host, args.p, args.c)
    client.main()
