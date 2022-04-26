'''
Author: Ben Ross
Date: 19/11/21
Outline:
This file holds a number of functions that
are useful throughout the messaging protocol'''

# Python Imports
import json


def extractBytesFromData(data: bytes, no_of_bytes: int) -> tuple[bytes, bytes]:
    '''Returns the first no_of_bytes bytes from the data object and slice the data.
    Returns (extract, sliced bytes)'''
    return data[:no_of_bytes], data[no_of_bytes:]


def intToBytes(x: int, order: str = 'big') -> bytes:
    '''Converts any size integer to bytes'''
    return x.to_bytes((x.bit_length() + 7) // 8, order)


def intFromBytes(xbytes: bytes, order: str ='big') -> int:
    '''Converts bytes to integer'''
    return int.from_bytes(xbytes, order)


def printBytes(to_print, row_size=16):
    '''Prints bytes in 16-long rows'''
    for rdx, i in enumerate(range(0, len(to_print), row_size)):
        row = [byte for byte in to_print[i:i+row_size]]
        byte_row = ' '.join(format(byte, 'x').zfill(2) for byte in row)
        ascii_rep = ''.join(chr(byte) if byte in range(32, 127) else '.' for byte in row)

        buffer = '   ' * (row_size - len(row))
        print(str(rdx*row_size).zfill(8) + '  ' + byte_row + '  ' + buffer + '|' + ascii_rep + '|')
    print()


def xorTwoBytes(bytes1: bytes, bytes2: bytes, byteorder='big') -> bytes:
    '''Xors two bytes. Really don't know why you can't do this natively
    within the byte type.'''
    int1: int = int.from_bytes(bytes1, byteorder)
    int2: int = int.from_bytes(bytes2, byteorder)
    return (int1 ^ int2).to_bytes(len(bytes1), byteorder)

def splitBytesIntoBlocks(data: bytes, block_size: int = 16) -> list[bytes]:
    '''Splits the data into block_size byte blocks.'''
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


def loadCurveParameters(curve_name: str) -> list[int]:
    '''Loads a curve from the json file'''
    with open('Cryptography/curves.json', 'r') as json_file:
        curves: dict = json.load(json_file)

    # Manipulate Data
    if curve_name not in curves:
        raise Exception('Curve Name Not Found')
    requested_curve_dict = curves[curve_name].items() # type = Dict Items
    requested_curve: list[int] = [value for _, value in requested_curve_dict]

    return requested_curve
 
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)
 
def modsqrt(n: int, p: int):
    '''Thanks to https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python'''
    assert legendre(n, p) == 1, "not a square (mod p)"

    q: int = p - 1
    s: int = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)

    z: int = 2
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c: int = pow(z, q, p)
    r: int = pow(n, (q + 1) // 2, p)
    t: int = pow(n, q, p)
    m: int = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        i: int = 1
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b: int = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r




if __name__ == '__main__':
    from os import system; system('clear')
    