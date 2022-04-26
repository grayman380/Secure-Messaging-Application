'''
Author: Ben Ross
Date: 7/9/21
Outline:
Holds the inner-algorithm for ChaCha20'''

# Python Imports
from typing import Generator

def rotateLeft(value: int, shift_size: int) -> int:
    '''Rotates the value by the given shift size'''
    return ((value << shift_size) & 0xffffffff)  | (value >> (32 - shift_size))


def addMod32(a, b):
    return (a + b) & 0xffffffff


def quarterRound(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    '''Runs a quarter round of the algorithm:
     a += b; d ^= a; d <<<= 16;
    c += d; b ^= c; b <<<= 12;
    a += b; d ^= a; d <<<= 8;
    c += d; b ^= c; b <<<= 7;'''

    a = addMod32(a, b); d ^= a; d = rotateLeft(d, 16)
    c = addMod32(c, d); b ^= c; b = rotateLeft(b, 12)
    a = addMod32(a, b); d ^= a; d = rotateLeft(d, 8)
    c = addMod32(c, d); b ^= c; b = rotateLeft(b, 7)
    return a, b, c, d



def convertBytesToWords(input_bytes: bytes, ) -> list[int]:
    '''Converts some bytes to 32-bit int arrays (words)'''
    return [int.from_bytes(input_bytes[i:i+4], 'little') for i in range(0, len(input_bytes), 4)]



def encryptOneBlock(block: list[int]) -> list[int]:
    '''Encrypts one block (s) using the ChaCha20 algorithm'''
    s: list[int] = block[:]

    for _ in range(10): # do column then diagonal in one loop
        # ODD ROUND: COLUMNS ###
        s[0], s[4], s[8], s[12] = quarterRound(s[0], s[4], s[8], s[12])
        s[1], s[5], s[9], s[13] = quarterRound(s[1], s[5], s[9], s[13])
        s[2], s[6], s[10], s[14] = quarterRound(s[2], s[6], s[10], s[14])
        s[3], s[7], s[11], s[15] = quarterRound(s[3], s[7], s[11], s[15])

        ### EVEN ROUND: DIAGONALLS ###
        s[0], s[5], s[10], s[15] = quarterRound(s[0], s[5], s[10], s[15]) # main diagonal
        s[1], s[6], s[11], s[12] = quarterRound(s[1], s[6], s[11], s[12])
        s[2], s[7], s[8], s[13] = quarterRound(s[2], s[7], s[8], s[13])
        s[3], s[4], s[9], s[14] = quarterRound(s[3], s[4], s[9], s[14])
        
    return [addMod32(b_value, s_value) for b_value, s_value in zip(block, s)]


def yieldChaChaEncryptedStream(byte_key: bytes, nonce: bytes, init_counter: int) -> Generator[int, None, None]:
    '''Runs 10 double rounds of chacha.
    Key is 32 bytes, but converted to eight words. Counter is one 32 bit int.
    Nonce is 12 bytes, but converted to three words'''

    assert len(byte_key) == 32

     
    block: list[int] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, # "expa" | "nd 3" | "2-by" | "te k" (little endian)
        *convertBytesToWords(byte_key),                   # key[:4], key[4:8], key[8:12], key[12:16],
                                                        # key[16:20], key[20:24], key[24:28], key[28:]
        init_counter, *convertBytesToWords(nonce)
    ]

    while True:
        # Serialize into bytes and yield
        for word in encryptOneBlock(block):
            for byte in word.to_bytes(4, 'little'):
                yield byte

        block[12] = addMod32(block[12], 1) # increment
    
    





if __name__ == '__main__':
    from os import system; system('clear')
    from time import perf_counter

    key = bytes(range(32))
    gen = yieldChaChaEncryptedStream(key, b'\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00', 1)


    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".encode()

    # ciphertext = bytes(a ^ b for a, b in zip(plaintext, gen))
    # printBytes(ciphertext)

    t = perf_counter()
    for _ in range(1000000):
        next(gen)
    print(f'Time Taken: {perf_counter() - t:.3f} secs')