'''
Author: Ben Ross
Date: 18/11/21
Outline:
This file holds the class for all AES functionality.
One instance of this class belongs to one user, with
one key per class. Key can be updated if needed.'''

# Python Imports
import secrets, hashlib
from multiprocessing import Queue, Process
from os import cpu_count
from turtle import xcor
from typing import Callable, Generator
from itertools import islice

# Local Imports
from Cryptography.HelpfulFunctions import xorTwoBytes, splitBytesIntoBlocks
from Cryptography.AESAlgorithm import expandKey, encryptBlock, encryptChunkOfBlocks

# Global Variables
I_PAD, O_PAD = 0x36, 0x5c
GHASH: Callable = hashlib.sha3_384
HASH_SIZE = GHASH('test'.encode()).digest_size


def generateNewAESKey(key_length: int=256) -> bytes:
    '''Generates a crpytographically random sequence
    of bytes of length key_length'''
    if key_length not in [128, 192, 256]:
        raise Exception('Invalid Key Size')
    return secrets.token_bytes(key_length // 8)


def buildNonceGenerator(iv: bytes, length: int) -> Generator[bytes, None, None]:
    '''Creates a generator that yields increments of a counter
    starting at one, in the from of a list, appened to the iv
    (initialisation vector),converted from bytes. The IV is 96
    bits (12 bytes), and the counter is a 32 bit integer (4 bytes)
    '''
    counter: int = 0
    for _ in range(length):
        counter += 1

        if counter > 4294967296:
            counter = 0

        yield iv + counter.to_bytes(4, 'big')


def generateCipherStream(nonce_generator: Generator[bytes, None, None], no_of_blocks: int, expanded_keys: list[bytes]) -> bytes:
    '''Encrypt all increments of the nonce generated from the
    nonce_generator, and return'''
    crypted_blocks: list[list[int]] = [[0]] * no_of_blocks # premake list

    no_of_rounds: int = len(expanded_keys) - 1
    
    # Main loop for encrypting
    for block_idx, block in enumerate(nonce_generator):
        crypted_blocks[block_idx] = encryptBlock(block, expanded_keys, no_of_rounds)
    
    return bytes(byte for block in crypted_blocks for byte in block) # flatten list


def generateCipherStreamConcurrently(nonce_generator: Generator[bytes, None, None], no_of_blocks: int, expanded_keys: list[bytes]) -> bytes:
    '''Encrypt all increments of the nonce generated from the
    nonce_generator, and return. Done with multiple processes
    running concurrently''' 
    # Setup multiproccessing
    queue: Queue = Queue()
    processes: list[Process] = []
    no_of_processes: int | None = cpu_count()
    if no_of_processes is None:
        raise Exception('CPU Count Returned None')

    # Setup chunks
    chunk_size: int = no_of_blocks // no_of_processes + 1
    crypted_chunks: list[list[int]] = []

    no_of_rounds: int = len(expanded_keys) - 1

    # Main loop for encrypting
    for chunk_idx, i in enumerate(range(0, no_of_blocks, chunk_size)):
        nonce_chunk: list[bytes] = list(islice(nonce_generator, chunk_size))

        process: Process = Process(target=encryptChunkOfBlocks, args=(queue, nonce_chunk, expanded_keys, chunk_idx, no_of_rounds))
        processes.append(process)
        process.start()

    # Get and order outputs
    crypted_chunks_with_idx: list[tuple[int, list[int]]] = [queue.get() for process in processes]
    crypted_chunks_with_idx.sort() # use the index to place the chunk in the correct spot
    crypted_chunks: list[list[int]] = [chunk[1] for chunk in crypted_chunks_with_idx]


    for process in processes:
        process.join()

    return bytes(byte for chunk in crypted_chunks for byte in chunk)


def generateGMAC(ciphertext: bytes, aad: bytes, iv: bytes, expanded_keys: list[bytes]) -> bytes:
    '''Uses the standard GCM procedure for creating a GMAC that secures the ciphertext. 
    Sources: https://en.wikipedia.org/wiki/Galois/Counter_Mode#Mathematical_basis
             https://youtu.be/R2SodepLWLg?t=201 (diagram)'''

    no_of_rounds: int = len(expanded_keys) - 1 # init variable

    # Initialise the GMAC with a hashkey of encrypted block of all zeroes
    hash_key: bytes = bytes(encryptBlock(bytes(16), expanded_keys, no_of_rounds))
    GMAC: bytes = GHASH(hash_key).digest()

    # Add padded aad to to GMAC
    padded_aad: bytes = aad + bytes(16 - len(aad) % 16)
    for aad_block in splitBytesIntoBlocks(padded_aad):
        GMAC = GHASH(xorTwoBytes(GMAC, aad_block)).digest()

    # Add padded ciphertext to GMAC
    padded_ciphertext: bytes = ciphertext + bytes(16 - len(aad) % 16)
    for ciphertext_block in splitBytesIntoBlocks(padded_ciphertext):
        GMAC = GHASH(xorTwoBytes(GMAC, ciphertext_block)).digest()
    
    # Add 64 bit lengths of aad and ciphertext to GMAC (concatenated)
    aad_length: bytes = len(aad).to_bytes(8, 'big')
    ciphertext_length: bytes = len(ciphertext).to_bytes(8, 'big')
    lengths: bytes = aad_length + ciphertext_length
    GMAC = GHASH(xorTwoBytes(GMAC, lengths)).digest()

    # Finally, add E(iv || 0^32) to GMAC
    encrypted_padded_iv: bytes = bytes(encryptBlock(iv + bytes(4), expanded_keys, no_of_rounds))
    return GHASH(xorTwoBytes(GMAC, encrypted_padded_iv)).digest()



def aesEncrypt(data: bytes, key: bytes, aad: bytes = b'', use_multiprocessing: bool = True) -> bytes:
    '''Main function for encrpyting some data.
    Returns GMAC || iv || ciphertext.
    len(GMAC) = 512 bits, len(iv) = 96 bits'''

    # Override use of multiprocessing if data too small
    if len(data) < 100000:
        use_multiprocessing = False

    # Define Variables
    expanded_keys: list[bytes] = expandKey(key)
    no_of_blocks: int = len(data) // 16 + 1
    iv: bytes = secrets.token_bytes(12) # 96 bits

    # Encrypt Data
    nonce_generator: Generator[bytes, None, None] = buildNonceGenerator(iv, no_of_blocks)
    if use_multiprocessing:
        encrypted_stream: bytes = generateCipherStreamConcurrently(nonce_generator, no_of_blocks, expanded_keys)
    else:
        encrypted_stream: bytes = generateCipherStream(nonce_generator, no_of_blocks, expanded_keys)
    ciphertext: bytes = bytes(a ^ b for a, b in zip(data, encrypted_stream))

    # generate GMAC
    gmac: bytes = generateGMAC(ciphertext, aad, iv, expanded_keys)

    return gmac + iv + ciphertext


def aesDecrypt(input_data: bytes, key: bytes, aad: bytes = b'', use_multiprocessing: bool = True) -> bytes:
    '''Main function for decrypting some data.'''
    expanded_keys: list[bytes] = expandKey(key) # expand keys

    # Split data
    stored_gmac: bytes = input_data[:HASH_SIZE]
    iv: bytes = input_data[HASH_SIZE:HASH_SIZE+12] # len(iv) = 12
    data: bytes = input_data[HASH_SIZE+12:]

    # HMAC generation and check
    generated_gmac: bytes = generateGMAC(data, aad, iv, expanded_keys)
    if not secrets.compare_digest(stored_gmac, generated_gmac):
        raise Exception('Incorrect GMAC generated. Some bits flipped or wrong key was used.')
    
    # Override use of multiprocessing if data too small
    if len(data) < 100000:
        use_multiprocessing = False

    no_of_blocks: int = len(data) // 16 + 1 # calculate the number of blocks

    # Decryption
    nonce_generator: Generator[bytes, None, None] = buildNonceGenerator(iv, no_of_blocks)
    if use_multiprocessing:
        encrypted_stream: bytes = generateCipherStreamConcurrently(nonce_generator, no_of_blocks, expanded_keys)
    else:
        encrypted_stream: bytes = generateCipherStream(nonce_generator, no_of_blocks, expanded_keys)
    plaintext: bytes = bytes(d_byte ^ e_byte for d_byte, e_byte in zip(data, encrypted_stream))

    return plaintext



def testing(filename: str):
    key: bytes = generateNewAESKey()
    aad: bytes = b'BENROSS'

    with open(filename, 'rb') as file:
        doc = file.read()

    print(f'{filename}:')

    t = perf_counter()
    print('Encrypting...', end='\r', flush=True)
    ciphertext: bytes = aesEncrypt(doc, key, aad)
    print(f'Encrypted in {perf_counter() - t:.3f} seconds')

    t = perf_counter()
    print('Decrypting...', end='\r', flush=True)
    plaintext: bytes = aesDecrypt(ciphertext, key, aad)
    print(f'Decrypted in {perf_counter() - t:.3f} seconds')

    print(f'{"SUCCESS" if doc == plaintext else "FAIL"}')
    print()



if __name__ == '__main__':
    from os import system; system('clear')
    from time import perf_counter

    testing('Cryptography/TestFiles/buddy.png')
    testing('Cryptography/TestFiles/4kdog.png')
    testing('Cryptography/TestFiles/wap.txt')
    