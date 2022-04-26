'''
Author: Ben Ross
Date: 16/1/22
Outline:
Holds a class of a double (really triple) ratchet mechanism
outlined by the signal protocol. Users will create an instance
of this class to keep perfect forward and backward secrecy in
the event a key gets comprimised.'''

# Python Imports
from hashlib import pbkdf2_hmac

# Local Imports
try:
    from AES import aesEncrypt, aesDecrypt
    from EllipticCurves import EllipticCurve, EllipticCurveKeys
    from HelpfulFunctions import loadCurveParameters, intToBytes, intFromBytes
except ModuleNotFoundError:
    from Cryptography.AES import aesEncrypt, aesDecrypt
    from Cryptography.EllipticCurves import EllipticCurve, EllipticCurveKeys
    from Cryptography.HelpfulFunctions import loadCurveParameters, intToBytes, intFromBytes

# Global Variables
MAX_SKIP: int = 20


class Header:
    '''A small class to help handle building header's for messages'''
    def __init__(self, dh_public_key: bytes, num_msgs_prev_chain: int, msg_num: int) -> None:
        self.dh_public_key: bytes = dh_public_key
        self.num_msgs_prev_chain: int = num_msgs_prev_chain
        self.msg_num: int = msg_num

    def __repr__(self):
        return f'({self.dh_public_key}, {self.num_msgs_prev_chain}, {self.msg_num})'

    def packIntoBytes(self) -> bytes:
        '''Creates a new message header containing the DH ratchet public key from dh_key_pair, 
        the previous chain length, and the message number. Returns 71 bytes.'''
        return self.dh_public_key + \
                self.num_msgs_prev_chain.to_bytes(2, 'big') + \
                self.msg_num.to_bytes(2, 'big')

    @staticmethod
    def unpackFromBytes(header_bytes: bytes):
        cpwps: int = len(header_bytes) - 4
        return Header(
            header_bytes[:cpwps],
            intFromBytes(header_bytes[cpwps:cpwps+2]), 
            intFromBytes(header_bytes[cpwps+2:])
        )



class DoubleRatchet:
    '''Based heavily on the explanations and sample code from:
    https://signal.org/docs/specifications/doubleratchet/'''

    def __init__(self, ec: EllipticCurve, shared_secret: bytes, init_dh_param: tuple[int, int] | EllipticCurveKeys) -> None:
        '''Prior to initialization both parties must use some key agreement protocol to agree
        on a 32-byte shared secret key and Bob's ratchet public key. Bob reaches out to Alice.'''

        self.ec: EllipticCurve = ec
        self.kdf_name: str = 'sha512'

        # Declaring variables that depend on if this ratchet is the first sender
        self.dh_key_pair: EllipticCurveKeys # the "sending" or "self" ratchet key
        self.dh_public_key: tuple[int, int] # the "received" or "remote" key
        self.root_key: bytes = shared_secret # 32 byte root key
        self.send_chain_key: bytes # 32 byte chain key for sending

        if isinstance(init_dh_param, tuple): # this is alice (being reached / sending initial message)
            self.dh_key_pair = self.ec.generateKeyPair()
            self.dh_public_key = init_dh_param # given bob's public key
            self.root_key, self.send_chain_key = self.updateRootRatchet(self.dh_key_pair, self.dh_public_key)

        else: # this is bob (reaching out)
            self.dh_key_pair = init_dh_param
            self.dh_public_key = (-1, -1) # default
            self.send_chain_key = b'' # default

        # Declaring the rest of the variables
        self.receive_chain_key: bytes = b'' # default
        self.sending_msg_num: int = 0 # Message numbers for sending
        self.receiving_msg_num: int = 0 # Message numbers for receiving
        self.num_msgs_prev_chain: int = 0 # Number of messages in previous sending chain

        # Dictionary of skipped-over message keys, indexed by ratchet public key and message number. Raises an exception if too many elements are stored.
        self.skipped_messages: dict[tuple[bytes, int], bytes] = {}
            

    def updateRootRatchet(self, dh_pair: EllipticCurveKeys, dh_pub: tuple[int, int]) -> tuple[bytes, bytes]:
        '''Updates the root key with the output of a DH exchange.'''
        # Perform DH exchange
        output_point: tuple[int, int] = self.ec.multiply(dh_pair.private, dh_pub)
        dh_output: bytes = intToBytes(self.ec.compressPoint(output_point))


        # Feed into kdf with root_key and return the root key and the chain key
        kdf_output: bytes = pbkdf2_hmac(self.kdf_name, self.root_key, dh_output, 1, 64)
        return kdf_output[:32], kdf_output[32:]

    def updateSendRatchet(self) -> bytes:
        '''Updates and returns the send chain key and the message key that was generated.'''
        '''Takes some secret to use as a salt while hashing the last
        used kdf key. This secret is the output of the diffie-hellman ratchet.
        Saves the next key for the kdf, returns the next output key'''
        kdf_output = pbkdf2_hmac(self.kdf_name, self.send_chain_key, b'', 1, 64)
        self.send_chain_key = kdf_output[:32]
        return kdf_output[32:]

    def updateReceiveRatchet(self) -> bytes:
        '''Updates and returns the send chain key and the message key that was generated.'''
        kdf_output = pbkdf2_hmac(self.kdf_name, self.receive_chain_key, b'', 1, 64)
        self.receive_chain_key = kdf_output[:32]
        return kdf_output[32:]



    def ratchetEncrypt(self, plaintext: bytes) -> bytes:
        '''This function performs a symmetric-key ratchet step, then encrypts the
        message with the resulting message key'''
        msg_key: bytes = self.updateSendRatchet()
        
        header: Header = Header(self.dh_key_pair.compPublicKeyAsBytes(), 
                                self.num_msgs_prev_chain, self.sending_msg_num)
        self.sending_msg_num += 1
        return header.packIntoBytes() + aesEncrypt(plaintext, msg_key, use_multiprocessing=False)



    def trySkippedMessageKeys(self, header: Header, ciphertext: bytes):
        '''Tests to see if this is a skipped message that's been previously recorded.'''
        if (header.dh_public_key, header.msg_num) not in self.skipped_messages:
            return b''

        # This is a skipped message
        msg_key: bytes = self.skipped_messages[(header.dh_public_key, header.msg_num)]
        del self.skipped_messages[(header.dh_public_key, header.msg_num)]
        return aesDecrypt(ciphertext, msg_key, use_multiprocessing=False)
    
    def skipMessageKeys(self, limit: int):
        if self.receiving_msg_num + MAX_SKIP < limit:
            raise Exception('Too many skipped messages')

        if self.receive_chain_key: # if it's been initialised
            while self.receiving_msg_num < limit:
                msg_key: bytes = self.updateReceiveRatchet()
                compressed_point: bytes = intToBytes(self.ec.compressPoint(self.dh_public_key))
                self.skipped_messages[(compressed_point, self.receiving_msg_num)] = msg_key
                self.receiving_msg_num += 1

    def updateDHRatchet(self, header: Header):
        # Reset counters
        self.num_msgs_prev_chain = self.sending_msg_num
        self.sending_msg_num = 0
        self.receiving_msg_num = 0

        # Get the peer's public key from the header
        self.dh_public_key = self.ec.decompressPoint(intFromBytes(header.dh_public_key))

        # Reset receive chain, reset the DH key, reset the send chain
        self.root_key, self.receive_chain_key = self.updateRootRatchet(self.dh_key_pair, self.dh_public_key)
        self.dh_key_pair = self.ec.generateKeyPair()
        self.root_key, self.send_chain_key = self.updateRootRatchet(self.dh_key_pair, self.dh_public_key)

    def ratchetDecrypt(self, ciphertext: bytes) -> bytes:
        ''' The function does the following:
            - If the message corresponds to a skipped message key this function decrypts the
              message, deletes the message key, and returns.
            - Otherwise, if a new ratchet key has been received this function stores any 
              skipped message keys from the receiving chain and performs a DH ratchet step 
              to replace the sending and receiving chains.
            - This function then stores any skipped message keys from the current receiving
              chain, performs a symmetric-key ratchet step to derive the relevant message key
              and next chain key, and decrypts the message.'''
        # Seperate header bytes and the ciphertext proper
        header_bytes: bytes = ciphertext[:self.ec.cpwps+4]
        ciphertext = ciphertext[self.ec.cpwps+4:]

        # Unpack header from bytes
        header: Header = Header.unpackFromBytes(header_bytes)

        # Check if this corresponds to a missed message
        plaintext = self.trySkippedMessageKeys(header, ciphertext)

        if plaintext: # if it was a missed messagex
            return plaintext


        if self.ec.decompressPoint(intFromBytes(header.dh_public_key)) != self.dh_public_key:
            self.skipMessageKeys(header.num_msgs_prev_chain)
            self.updateDHRatchet(header)
        
        self.skipMessageKeys(header.msg_num)

        msg_key: bytes = self.updateReceiveRatchet()
        self.receiving_msg_num += 1

        return aesDecrypt(ciphertext, msg_key)











if __name__ == '__main__':
    from os import system; system('clear')

    ec: EllipticCurve = EllipticCurve('P-521')

    init_bob_keys: EllipticCurveKeys = ec.generateKeyPair()
    shared_secret: bytes = bytes(range(32))


    bob: DoubleRatchet = DoubleRatchet(ec, shared_secret, init_bob_keys)
    alice: DoubleRatchet = DoubleRatchet(ec, shared_secret, init_bob_keys.public)

    ct1 = alice.ratchetEncrypt(b'A -> B 1')
    ct2 = alice.ratchetEncrypt(b'A -> B 2')
    ct3 = bob.ratchetEncrypt(b'B -> A 1')

    assert bob.ratchetDecrypt(ct1) == b'A -> B 1'
    assert alice.ratchetDecrypt(ct3) == b'B -> A 1'
    assert bob.ratchetDecrypt(ct2) == b'A -> B 2'







    


