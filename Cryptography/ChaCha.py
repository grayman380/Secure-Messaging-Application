'''
Author: Ben Ross
Date: 7/12/21
Outline:
This file holds all ChaCha20 functionality.
One instance of thisclass belonds to one user, with
one key per class. Key can be updated if needed.'''

# Python Imports
import secrets, hashlib
from itertools import islice
from typing import Any, Generator

# Local Imports
try:
    from HelpfulFunctions import intToBytes, intFromBytes
    from ChaChaAlgorithm import yieldChaChaEncryptedStream
except ModuleNotFoundError:
    from Cryptography.HelpfulFunctions import intToBytes, intFromBytes
    from Cryptography.ChaChaAlgorithm import yieldChaChaEncryptedStream

# Global Variables
I_PAD, O_PAD = 0x36, 0x5c

class ChaCha20:
    '''Holds methods for AES encryption. Only input 
    variable is length of key'''

    def __init__(self, key: bytes) -> None:
        '''Key must be given as a parameter'''
        self.key: bytes = key
        self.key_length: int = 256
        
        self.GHASH: Any = hashlib.sha3_512


    @staticmethod
    def generateNewKey() -> bytes:
        '''Generates a crpytographically random sequence
        of bytes of length 256 bits'''
        return secrets.token_bytes(32) # 256 / 8 = 32


    @staticmethod
    def getNonce() -> bytes:
        '''Gets the 48-bit counter from the file and appends
        it to a 48-bit cryptographically secure random number.
        The counter is then incremented and the nonce is returned.'''

        # Get counter from file
        with open('Cryptography/poly1305Counter.txt', 'r') as infile:
            counter = int(infile.read())

        # Increment counter and save to file
        with open('Cryptography/poly1305Counter.txt', 'w') as outfile:
            outfile.write(str(counter + 1))

        # Generate random component and combine with counter
        random = secrets.token_bytes(6) # 48 / 8 = 6
        return random + counter.to_bytes(6, 'little')

    @staticmethod
    def padTo16(data: bytes) -> bytes:
        return bytes(16 - len(data) % 16)


    def setKey(self, key: bytes) -> None:
        '''Sets the classes key to the given key'''
        self.key = key


    def generatePoly1305Key(self, nonce: bytes) -> bytes:
        '''Follows RFC 7539, section 2.6:
        https://www.rfc-editor.org/rfc/rfc7539#section-2.6'''
        # Gets the first 32 bytes for the poly1305 key
        return bytes(islice(yieldChaChaEncryptedStream(self.key, nonce, 0), 32))



    def poly1305(self, data: bytes, otk: bytes) -> bytes:
        '''Follows the poly1305 algoithm from RFC 7539, section 2.5:
        https://www.rfc-editor.org/rfc/rfc7539#section-2.5'''
        

        # Define, clamp and convert r to int
        r_list: list[int] = list(otk[:16])
        r_list[3] &= 15; r_list[7] &= 15; r_list[11] &= 15; r_list[15] &= 15
        r_list[4] &= 252; r_list[8] &= 252; r_list[12] &= 252
        r: int = intFromBytes(bytes(r_list), order='little')
        
        # Define and convert s to int
        s_bytes: bytes = otk[16:]
        s: int = intFromBytes(s_bytes, order='little')

        # Define accumlator and constant prime P
        accumulator: int = 0
        P: int = 2**130 - 5

        # Add to the accumulator for each block
        for block in (data[i:i+16] for i in range(0, len(data), 16)):
            n: int = intFromBytes(block + b'\x01', order='little')
            accumulator += n
            accumulator = (r * accumulator) % P

        accumulator += s

        tag: bytes = intToBytes(accumulator, order='little')[:16] # get 16 lsb
        return tag + bytes(16 - len(tag)) # add padding if necessary



    def encrypt(self, data: bytes, aad: bytes = b'', nonce: bytes = b'', starting_block: int = 1) -> bytes:
        '''The main encryption function.
        Follows the process of AEAD construction from RFC 7539, section 2.8:
        https://www.rfc-editor.org/rfc/rfc7539#section-2.8'''

        # Generate random nonce (I know this isn't good practice but idc)
        if not nonce: # if a nonce isn't given, generate it randomly
            nonce = secrets.token_bytes(12)

        # Generate otk for poly1305
        otk: bytes = self.generatePoly1305Key(nonce)

        # Encrypt Data
        byte_generator: Generator[int, None, None] = yieldChaChaEncryptedStream(self.key, nonce, starting_block)
        ciphertext: bytes = bytes(a ^ b for a, b in zip(data, byte_generator))

        # Generate Authentication Code
        mac_data: bytes = aad + ChaCha20.padTo16(aad)
        mac_data += ciphertext + ChaCha20.padTo16(ciphertext)
        mac_data += len(aad).to_bytes(8, 'little')
        mac_data += len(ciphertext).to_bytes(8, 'little')
        
        tag: bytes = self.poly1305(mac_data, otk)

        return tag + nonce + ciphertext


    def decrypt(self, data: bytes, aad: bytes = b'') -> bytes:
        '''The main decryption function.
        Follows the process of AEAD construction from RFC 7539, section 2.8:
        https://www.rfc-editor.org/rfc/rfc7539#section-2.8'''

        # Split data
        stored_tag: bytes = data[:16] # 128 / 8 = 16
        nonce: bytes = data[16:28] # 96 / 8 = 12 => (16 + 12 = 28)
        ciphertext: bytes = data[28:]

        # Generate Authentication Code
        otk: bytes = self.generatePoly1305Key(nonce)
        mac_data: bytes = aad + ChaCha20.padTo16(aad)
        mac_data += ciphertext + ChaCha20.padTo16(ciphertext)
        mac_data += len(aad).to_bytes(8, 'little')
        mac_data += len(ciphertext).to_bytes(8, 'little')
        generated_tag: bytes = self.poly1305(mac_data, otk)

        # Compare Tags (Safe from timing attacks)
        if not secrets.compare_digest(stored_tag, generated_tag):
            raise Exception('Inccorrect MAC tag generated. Some bits flipped or wrong key was used')
        
        # Decrypt Data
        byte_generator: Generator[int, None, None] = yieldChaChaEncryptedStream(self.key, nonce, 1)
        plaintext: bytes = bytes(a ^ b for a, b in zip(ciphertext, byte_generator))

        return plaintext



def test():
    # Testing according to RFC Exaple 2.8.2
    # https://www.rfc-editor.org/rfc/rfc7539#section-2.8.2

    key = bytes(range(128, 160))
    chacha1 = ChaCha20(key)
    chacha2 = ChaCha20(key)

    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".encode()
    nonce = b'\x07\x00\x00\x00' + b'\x40\x41\x42\x43\x44\x45\x46\x47'
    aad = b'\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7'



    output1: bytes = chacha1.encrypt(plaintext, aad, nonce)
    assert output1 == b'\x1a\xe1\x0bYO\t\xe2j~\x90.\xcb\xd0`\x06\x91\x07\x00\x00\x00@ABCDEFG\xd3\x1a\x8d4d\x8e`\xdb{\x86\xaf\xbcS\xef~\xc2\xa4\xad\xedQ)n\x08\xfe\xa9\xe2\xb5\xa76\xeeb\xd6=\xbe\xa4^\x8c\xa9g\x12\x82\xfa\xfbi\xda\x92r\x8b\x1aq\xde\n\x9e\x06\x0b)\x05\xd6\xa5\xb6~\xcd;6\x92\xdd\xbd\x7f-w\x8b\x8c\x98\x03\xae\xe3(\t\x1bX\xfa\xb3$\xe4\xfa\xd6u\x94U\x85\x80\x8bH1\xd7\xbc?\xf4\xde\xf0\x8eKz\x9d\xe5v\xd2e\x86\xce\xc6Ka\x16'

    output2 = chacha2.decrypt(output1, aad)
    assert output2 == plaintext


def test2():

    key = secrets.token_bytes(32)
    chacha1 = ChaCha20(key)

    with open('Cryptography/TestFiles/buddy.png', 'rb') as file:
        doc = file.read()


    nonce = ChaCha20.getNonce()
    aad = 'Ben Ross'.encode()

    t = perf_counter()
    print('Encrypting...', end='\r', flush=True)
    ciphertext = chacha1.encrypt(doc, aad, nonce)
    print(f'Encrypted in {perf_counter() - t:.3f} seconds')

    t = perf_counter()
    print('Decrypting...', end='\r', flush=True)
    plaintext = chacha1.decrypt(ciphertext, aad)
    print(f'Decrypted in {perf_counter() - t:.3f} seconds')

    print(f'{"SUCCESS" if doc == plaintext else "FAIL"}')


if __name__ == '__main__':
    from os import system; system('clear')
    from time import perf_counter

    # Testing according to RFC Exaple 2.8.2
    # https://www.rfc-editor.org/rfc/rfc7539#section-2.8.2

    test()
    test2()

    



    

