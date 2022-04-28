'''
Author: Ben Ross
Date: 26/12/21
Outline:
This file holds all of the logic for running the
server of the application.'''

# Python Imports
from threading import Thread
from hashlib import pbkdf2_hmac
from secrets import token_bytes, compare_digest, choice
from argparse import ArgumentParser
from string import ascii_lowercase, digits
import socket, sqlite3, pickle
from json import dump, load
from os import path

# Local Imports
from Cryptography.AES import aesEncrypt, aesDecrypt
from Cryptography.EllipticCurves import EllipticCurve, EllipticCurveKeys


# Global Variables
CHARACTER_SET: set[str] = set(ascii_lowercase + digits)
SERVER_UID: str = '0'*16
RECV_BUFFER_SIZE: int = 1024


def refreshServerKeys():
    '''Generates new elliptic curve keys for each curve size and saves them'''
    print('Generating New Server Keys... ', end='', flush=True)
    key_dict: dict[str, dict[str, int]] = EllipticCurve.generateKeysForAllCurves()
    with open('ServerKeys.json', 'w') as file:
        dump(key_dict, file)
    print('Done')


class ServerSocket(Thread):

    def __init__(self, sock: socket.socket, sockname: str, server):
        super().__init__(daemon=True)
        self.sock: socket.socket = sock
        self.sockname: str = sockname
        self.server: Server = server
        
        self.running: bool = True
        self.uid: str = ''
        self.shared_key: bytes = b''
        self.registered_this_session: bool
        self.comp_public_IK: bytes
        self.comp_public_SPK: bytes

    #####################################################################################
    # SERVER COMMAND METHODS
    def initialECDHE_ECDSA(self, data_dict: dict) -> None:
        '''Ephemeral ECDH signed with ECDSA'''
        # Unload the curve name and the client's ephemeral public key
        curve_name: str = data_dict['curve_name']
        client_ephemeral_public: tuple[int, int] = data_dict['client_ephemeral_public']

        # Build ec object and load keys from file
        with open('ServerKeys.json', 'r') as file:
            key_from_file = load(file)[curve_name]
        self.ec: EllipticCurve = EllipticCurve(curve_name)
        self.keys: EllipticCurveKeys = EllipticCurveKeys(key_from_file['CompressedPublic'],
                                                        key_from_file['Private'], self.ec)

        # Generate random integer and point on curve. Build document and sign
        ephemeral_keys: EllipticCurveKeys = self.ec.generateKeyPair()
        document: bytes = token_bytes(16) + bytes.fromhex('5341564557494e53544f4e534d495448')
        signature: bytes = self.ec.sign(document, self.keys.private)

        # Accumulate and pickle the server's public key, ephemeral public key, the document and signature, then send
        pickled_data: bytes = pickle.dumps({'public_IKs': self.keys.public,
                                            'public_EKs': ephemeral_keys.public,
                                            'document': document, 'signature': signature})
        self.sendData(pickled_data)

        # Generate the shared key by multiplying the client's point by your random integer
        dh_output: bytes = self.ec.encodePoint(self.ec.multiply(ephemeral_keys.private, client_ephemeral_public))
        self.shared_key: bytes = pbkdf2_hmac('sha3_256', dh_output, bytes(16), 100000) # 256 bit key

    def registerUIDCommand(self) -> None:
        '''Handles the RegisterUID command from the client.
        Generates a fresh, unused uid, saves it, and sends it to them.'''
        self.uid = self.server.generateUnusedUID()
        self.sendData(self.uid.encode())

    def registerPasswordCommand(self, data_dict: dict) -> None:
        '''Handles the RegisterPassword command from the client.
        Receives a salt, hashed password and public identity keys for each curve size
        and adds them to the server's database.'''
        salt: bytes = data_dict['salt']
        hashed_password: bytes = data_dict['hashed_password']
        public_IKs: dict[str, bytes] = data_dict['public_IKs']
        self.comp_public_IK: bytes = public_IKs[self.ec.name]

        if self.server.addLoginToDatabase(self.uid, salt, hashed_password, public_IKs):
            self.registered_this_session = True
            self.sendData(b'Registration Successful')
            self.server.online[self.uid] = self
        else:
            self.sendData(b'Registration Failed.')

    def loginUIDCommand(self, data_dict: dict) -> None:
        '''Handles the LoginUID command from the client.
        Simply saves the uid the client sent.'''
        self.uid: str = data_dict['uid']

    def loginPasswordCommand(self, data_dict: dict) -> None:
        '''Handles the LoginPassword command from the client.
        Recevies a password from the client and checks if it matches the password that the server
        has saved in it's database corresponding to the uid the client send with the LoginUID
        command. Also gets the user's identity key from the databse if it matches.'''
        password: str = data_dict['password']

        if self.server.checkIfPasswordMatches(self.uid, password):
            self.registered_this_session = False
            self.server.online[self.uid] = self
            self.comp_public_IK = self.server.getPublicIKFromDatabase(self.uid, self.ec.name)
            self.sendData(b'Login Successful')
        else:
            self.sendData(b'Login Failed.')

    def queryUIDCommand(self, data_dict: dict) -> None:
        '''Handles the QueryUID command from the client.
        Receives a uid from the client that the server checks against it's list of
        currently active clients.'''
        self.sendData(b'online' if data_dict['uid'] in self.server.online else b'offline')

    def sharePrekeyBundleCommand(self, data_dict: dict) -> None:
        '''Handles the SharePrekeyBundle command from the client.
        Receives an encoded signing public key, a signature of that signing public key signed
        with the client's identity public key, and a list of one time public keys. The server
        also tests if the signature is valid.'''
        self.encoded_SPK: bytes = data_dict['encoded_SPK']
        self.signature: bytes = data_dict['signature']
        self.OPKs: list[tuple[int, int]] = data_dict['OPKs']

        assert self.ec.verify(self.signature, self.encoded_SPK, 
                self.ec.decompressPoint(self.comp_public_IK)), 'Prekey Bundle Signature Invalid'

    def establishConnectionCommand(self, data_dict: dict) -> None:
        '''Handles the EstablishConnection command from the client.
        Receives a uid from the client (Alice), then uses it to look up the requested client's (Bob)
        prekey bundle. The server then sends the prekey bundle back to the client with the command
        X3DH, indicating that they are receiving a prekey bundle for use in a X3DH.'''

        requested: str = data_dict['peer_uid']
        print(f'{self.uid} is trying to connect to {requested}')

        bob: ServerSocket = self.server.online[requested]

        # Accumulate and pickle prekey bundle, then send
        pickled_data: bytes = pickle.dumps({
            'IPK': bob.comp_public_IK, 'SPK': bob.encoded_SPK, 
            'signature': bob.signature, 'OPK': bob.OPKs.pop()                    
        })
        self.sendData(b'X3DH' + pickled_data)

    def handleServerData(self, data: bytes) -> None:
        '''Handles all of the logic for server tasks'''
        # Print the data received
        printed_sender: str = self.uid if self.uid else self.sockname
        to_print: bytes = data[:30] + b'...' if len(data) > 30 else data
        print(f'{printed_sender} -> _____SERVER_____: {to_print}')

        data_dict: dict = pickle.loads(data)
        match data_dict['cmd']:            
            case 'InitDiffieHellman': # client is establishing a shared key
                self.initialECDHE_ECDSA(data_dict)

            case 'RegisterUID': # client wants to register (client is requesting a uid)
                self.registerUIDCommand()

            case 'RegisterPassword': # client is inputting a password to be registered
                self.registerPasswordCommand(data_dict)

            case 'LoginUID': # client wants to login (client is inputting a uid to login)
                self.loginUIDCommand(data_dict)

            case 'LoginPassword': # client is inputting a password to login
                self.loginPasswordCommand(data_dict)
                
            case 'QueryUID': # client is aksing the server is a uid (another client) is online
                self.queryUIDCommand(data_dict)

            case 'SharePrekeyBundle': # client is sharing their prekey bundle
                self.sharePrekeyBundleCommand(data_dict)

            case 'EstablishConnection':
                self.establishConnectionCommand(data_dict)

            case _:
                raise Exception(f"Invalid Command Given: {data_dict['cmd']}")

    #####################################################################################
    # SENDING DATA METHODS
    def sendData(self, data: bytes, sender: str = SERVER_UID) -> None:
        '''Sends some data to the socket (user). The sender is also noted. 
        The default is 16 zeroes, indicating the server is sending the message'''
        printed_sender: str = '_____SERVER_____' if sender == SERVER_UID else sender
        printed_receiver: str = self.uid if self.uid else self.sockname
        to_print: bytes = data[:40] + b'...' if len(data) > 40 else data
        print(f'{printed_sender} -> {printed_receiver}: {to_print}')

        pickled_data: bytes = pickle.dumps((sender, data))
        encrypted_data: bytes = aesEncrypt(pickled_data, self.shared_key) if self.shared_key else pickled_data

        data_length: bytes = len(encrypted_data).to_bytes(4, 'big')
        self.sock.sendall(data_length + encrypted_data)

    #####################################################################################
    # RECEIVING DATA METHODS
    def handlePeerToPeerData(self, message: bytes, recipient: str) -> None:
        '''Handles all of the logic for relaying a message to another client.'''
        if recipient in self.server.online:
            self.server.online[recipient].sendData(message, self.uid) # pass it on
        else:
            # self.sendData(f'User: {recipient} is not online'.encode())
            print(f'User: {recipient} is not online')

    def processReceivedData(self, recipient: str, message: bytes) -> bool:
        '''Anaylses the data received and acts accordingly.
        Return false, if no data was received (lost connection
        with the client), else true'''
        if message == b'':
            return False

        if recipient == SERVER_UID: # data for the server
            self.handleServerData(message)
        else:                       # data for another user
            self.handlePeerToPeerData(message, recipient)

        return True

    def receiveData(self) -> tuple[str, bytes]:
        '''Receives some data from the socket (user)'''
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


    def run(self):
        recipient: str
        message: bytes

        while self.running:
            try:
                recipient, message = self.receiveData()
            except OSError: # kill thread
                if self.uid in self.server.online: # if the uid has been created and added already
                    del self.server.online[self.uid]
                return 

            if not self.processReceivedData(recipient, message):
                print(f'\n{self.sockname} has closed the connection')
                self.sock.close()
                self.server.removeConnection(self)


class Server(Thread):

    def __init__(self, host, port) -> None:
        super().__init__(daemon=True)
        self.host: str = host
        self.port: int = port

        self.connections: list[ServerSocket] = []
        self.online: dict[str, ServerSocket] = {}
        self.conversation_requests: set[tuple[str, str]] = set()

        self.running: bool = True

        # Database stuff
        self.setupDatabse()

    def setupDatabse(self) -> None:
        '''Sets up the database using sqlite3'''
        database_exists: bool = path.exists('database.db')

        self.conn = sqlite3.connect('database.db', check_same_thread=False)
        self.cursor = self.conn.cursor()

        if not database_exists:
            with self.conn:
                self.cursor.execute('''CREATE TABLE logins (uid text, salt text,
                password text, ik_224 text, ik_256 text, ik_384 text, ik_521 text)''')


    def addLoginToDatabase(self, uid: str, salt: bytes, hashed_password: bytes, public_IKs: dict[str, bytes]) -> bool:
        '''Takes a uid and password has strings, hashes and salts
        the password correctly, then stores in the database.
        Returns true if successful, false if uid already exists.'''
        with self.conn:
            self.cursor.execute('SELECT * FROM logins WHERE uid=:uid', {'uid': uid})
            if self.cursor.fetchone() is not None: # if login already exists
                return False

            self.cursor.execute('''INSERT INTO logins VALUES (:uid, :salt, :password, :ik_224,
                                    :ik_256, :ik_384, :ik_521)''',
                {'uid': uid, 'salt': salt.hex(), 'password': hashed_password.hex(), 'ik_224': public_IKs['P-224'].hex(),
                'ik_256': public_IKs['P-256'].hex(), 'ik_384': public_IKs['P-384'].hex(), 'ik_521': public_IKs['P-521'].hex()})

        return True

    def checkIfPasswordMatches(self, uid: str, password: str) -> bool:
        '''Returns whether or not the password entered matches the
        database given a uid. This is done using a method that is
        safe from timing attacks.'''
        # if the uid is already online, the user shouldn't be able to log in
        if uid in self.online:
            return False

        with self.conn:
            self.cursor.execute('SELECT * FROM logins WHERE uid=:uid', {'uid': uid})
        result: tuple[str, str, str] | None = self.cursor.fetchone()

        if result is None: # uid isn't in the database, so return a fail
            return False

        salt: bytes = bytes.fromhex(result[1])
        correct_password: bytes = bytes.fromhex(result[2])

        entered_password: bytes = pbkdf2_hmac('sha3_512', password.encode(), salt, 100000)

        return compare_digest(entered_password, correct_password)

    def getPublicIKFromDatabase(self, uid: str, curve_name: str) -> bytes:
        '''Returns the compressed public IK that is associated with the given uid.
        Entry is guaranteed to exists as the method is only called after previous checks'''
        column_name: str = 'ik_' + curve_name[-3:]
        with self.conn:
            self.cursor.execute('SELECT ' + column_name + ' FROM logins WHERE uid=:uid', {'uid': uid})
        return bytes.fromhex(self.cursor.fetchone()[0])


    def generateUnusedUID(self) -> str:
        '''Randomly generates a new uid that hasn't be registered before.'''
        # TODO: Remove testing default

        def generateRandomUID() -> str:
            return ''.join(choice(list(CHARACTER_SET)) for _ in range(16))

        def isUIDAvailable(uid):
            with self.conn:
                self.cursor.execute('SELECT * FROM logins WHERE uid=:uid', {'uid': uid})
            return self.cursor.fetchone() is None
        
        while not isUIDAvailable(uid := generateRandomUID()):
            pass

        return uid


    def removeConnection(self, connection: ServerSocket) -> None:
        self.connections.remove(connection)


    def run(self):
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        self.sock.listen(1)
        print(f'Listening at {self.sock.getsockname()}')

        while self.running:
            # Accepting new connection
            sc, sockname = self.sock.accept()
            print(f'\nAccepting new connection from {sc.getpeername()} to {sc.getsockname()}')

            server_socket: ServerSocket = ServerSocket(sc, sockname, self) # Create a new thread
            server_socket.start() # Start new thread

            # Add thread to active connection
            self.connections.append(server_socket)
            print(f'Ready to receive message from {sc.getpeername()}')



def exit(server: Server):
    while True:
        ipt = input('')

        if ipt == 'q':
            print('\nClosing all connections... ', end='', flush=True)

            for connection in server.connections:
                connection.running = False # close connection
            print('Done')

            print('Shutting down the server')
            server.running = False # stop the server thread
            return



if __name__ == '__main__':
    from os import system; system('clear')

    parser: ArgumentParser = ArgumentParser(description='Chat App Server')
    parser.add_argument('-host', metavar='HOST', type=str, default='NoneGiven', help='IP Address')
    parser.add_argument('-port', metavar='PORT', type=int, default=6174, help='TCP port(default 6174)')
    parser.add_argument('-refreshkeys', dest='refreshkeys', default=False, action='store_true', help='Refresh the server\'s keys')

    args = parser.parse_args()
    
    # Deal with host
    if args.host == 'NoneGiven':
        from subprocess import Popen, PIPE
        # Bash command for getting this computer's IP address
        sp: Popen = Popen("ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{ print $2 }'", shell=True, stdout=PIPE)
        if sp.stdout is not None:
            args.host = sp.stdout.read()[:-1].decode() # remove the newline character at the end
        else:
            args.host = 'localhost' # default in case command goes wrong

    # Deal with refreshkeys
    if args.refreshkeys or not path.exists('ServerKeys.json'):
        refreshServerKeys()
    
    # Create and start server thread
    server = Server(args.host, args.port)
    server.start()

    exit_thread: Thread = Thread(target=exit, args=(server,), daemon=True)
    exit_thread.start()
    exit_thread.join()



