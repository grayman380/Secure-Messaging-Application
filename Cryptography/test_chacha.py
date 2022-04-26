#!/usr/bin/env python
'''Testing File for all AES functions'''

# Local Imports
from typing import Iterator
from ChaChaAlgorithm import *
from ChaCha import ChaCha20

# Python Imports
import unittest, json, itertools


def convertFromByteGrid(grid: str) -> bytes:
    '''Converts a grid of hex bytes as shown in the RFC 7539 
    test vectors to a bytes object'''
    # f_grid: list[str] = list(filter(lambda c: c in '0123456789abcdef', grid))
    # return bytes(int(f_grid[i] + f_grid[i+1], 16) for i in range(0, len(f_grid), 2))
    return bytes(int(byte, 16) for byte in grid.strip().split())


class TestChaCha(unittest.TestCase):

    def setUp(self) -> None:
        with open('Cryptography/ChaChaTestCases.json', 'r') as file:
            self.test_cases = json.load(file)

        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_blockFunctions(self):
        # '''Tests the block functions of the cipher (AXR operations)'''
        for test_dict in self.test_cases['Block Functions']:
            # Get data from file
            key = convertFromByteGrid(test_dict['key'])
            nonce = convertFromByteGrid(test_dict['nonce'])
            block_counter = test_dict['block counter']
            true_keystream = convertFromByteGrid(test_dict['keystream'])

            # Generate data and compare
            generated_keystream = bytes(itertools.islice(yieldChaChaEncryptedStream(key, nonce, block_counter), 64))
            self.assertEqual(generated_keystream, true_keystream)


    def test_encryption(self):
        # '''Tests the encryption of some plaintext using the cipher'''
        for test_dict in self.test_cases['Encryption']:
            # Get data from file
            key = convertFromByteGrid(test_dict['key'])
            nonce = convertFromByteGrid(test_dict['nonce'])
            block_counter = test_dict['block counter']
            plaintext = convertFromByteGrid(test_dict['plaintext'])
            true_ciphertext = convertFromByteGrid(test_dict['ciphertext'])

            # Generate data and compare
            chacha = ChaCha20(key)
            generated_ciphertext = chacha.encrypt(plaintext, nonce=nonce, starting_block=block_counter)[28:] # cuts off tag and nonce

            self.assertEqual(generated_ciphertext, true_ciphertext)


    def test_poly1305MAC(self):
        # '''Tests the encryption of some plaintext using the cipher'''
        for test_dict in self.test_cases['poly1305 MAC']:
            # Get data from file
            otk = convertFromByteGrid(test_dict['otk'])
            plaintext = convertFromByteGrid(test_dict['plaintext'])
            true_tag = convertFromByteGrid(test_dict['tag'])

            # Generate data and compare
            chacha = ChaCha20(bytes(32)) # key isn't relevant here
            generated_tag = chacha.poly1305(plaintext, otk)

            self.assertEqual(generated_tag, true_tag)


    def test_poly1305KeyGeneration(self):
        # '''Tests the encryption of some plaintext using the cipher'''
        for test_dict in self.test_cases['poly1305 Key Generation']:
            # Get data from file
            key = convertFromByteGrid(test_dict['key'])
            nonce = convertFromByteGrid(test_dict['nonce'])
            true_otk = convertFromByteGrid(test_dict['otk'])

            # Generate data and compare
            chacha = ChaCha20(key)
            generated_otk = chacha.generatePoly1305Key(nonce)

            self.assertEqual(generated_otk, true_otk)


    def test_Decryption(self):
        # '''Tests the ChaCha20-Poly1305 AEAD Decryption'''

        # Setup (received) data
        key = convertFromByteGrid('1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0')
        ciphertext = convertFromByteGrid('64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd 5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2 4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0 bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf 33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81 14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55 97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38 36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4 b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9 90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a 0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a 0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10 49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30 30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29 a6 ad 5c b4 02 2b 02 70 9b')
        nonce = convertFromByteGrid('00 00 00 00 01 02 03 04 05 06 07 08')
        aad = convertFromByteGrid('f3 33 88 86 00 00 00 00 00 00 4e 91')
        tag = convertFromByteGrid('ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38')

        true_plaintext = convertFromByteGrid('49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20 61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65 6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20 6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d 6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65 20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63 65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64 20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65 6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e 20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72 69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72 65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61 6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65 6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20 2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67 72 65 73 73 2e 2f e2 80 9d')

        # Generate and compare
        chacha = ChaCha20(key)
        generated_plaintext = chacha.decrypt(tag + nonce + ciphertext, aad)

        self.assertEqual(true_plaintext, generated_plaintext)



    # def test_encrypt(self):
    #     pass

    # def test_decrypt(self):
    #     pass


    

if __name__ == '__main__':
    import os
    os.system('clear')

    unittest.main(verbosity=2)
