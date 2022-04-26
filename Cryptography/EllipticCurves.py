
# Python Imports
from ast import Call
import secrets, hashlib
from tracemalloc import Statistic
from typing import Callable
from math import ceil

# Local Imports
from Cryptography.HelpfulFunctions import *
from Cryptography.AES import aesEncrypt, aesDecrypt

# Global Variables
INF_POINT = (-1, -1)



class EllipticCurveKeys:
    '''Holds information for elliptic curve keys.
    Will learn how to do compressed keys and montgomery 
    ladder shit at some point. No idea what that means right now'''

    def __init__(self, compressed_public: int | bytes, private: int | bytes, ec) -> None:
        self.ec = ec
        self.compressed_public: int = intFromBytes(compressed_public) if isinstance(compressed_public, bytes) else compressed_public
        self.public = self.ec.decompressPoint(self.compressed_public)
        self.private: int = intFromBytes(private) if isinstance(private, bytes) else private

    def __repr__(self):
        return f'Public: {self.compPublicKeyAsBytes()}\nPrivate: {self.privateKeyAsBytes()}'

    def compPublicKeyAsBytes(self) -> bytes:
        return self.compressed_public.to_bytes(self.ec.cpwps, 'big')

    def publicKeyAsBytes(self) -> tuple[bytes, bytes]:
        '''Returns the public key as a tuple of bytes instrad of ints'''
        return (self.public[0].to_bytes(self.ec.byte_point_length, 'big'),
                self.public[1].to_bytes(self.ec.byte_point_length, 'big'))

    def privateKeyAsBytes(self) -> bytes:
        return self.private.to_bytes(self.ec.byte_point_length, 'big')



class EllipticCurve:
    def __init__(self, name) -> None:
        self.name = name
        parameters = loadCurveParameters(self.name)


        self.validateParameters(name, parameters) # raises exception if invalid parameter(s)

        # Equation Parameters
        self.name = name
        self.p: int = parameters[0]
        self.a: int = parameters[1]
        self.b: int = parameters[2]

        # Generator Point
        self.Gx: int = parameters[3]
        self.Gy: int = parameters[4]
        self.G: tuple[int, int] = (self.Gx, self.Gy)

        # Order and Cofactor
        self.n: int = parameters[5]
        self.h: int = parameters[6]

        # Misc
        self.kdf_name: str = 'sha3_256'
        self.hash: Callable = hashlib.sha256
        self.byte_point_length = ceil(self.getKeyLength() / 8)
        self.cpwps: int = self.byte_point_length + 1 # comp_point_with_prefix_size
        self.signature_size: int = self.byte_point_length * 2


    def validateParameters(self, name, parameters) -> None:
        '''Length + Type Checking for the Parameters'''
        if len(parameters) != 7:
            raise ValueError('Invalid Curve')

        # Name Check
        if not isinstance(name, str):
            raise ValueError('Invalid Curve. Name isn\'t a string.')

        # Equation Parameters, Generator Point, and Order & Cofactor Check
        if not all(isinstance(param, int) for param in parameters):
            raise ValueError('Invalid Curve. One or more curve parameters aren\'t integers')
        

    def addition(self, P1: tuple[int, int], P2: tuple[int, int]) -> tuple[int, int]:
        '''Adds two points on the curve together'''
        # Handle 'point at infitity'. It's the identity
        if P1 == INF_POINT and P2 == INF_POINT:
            raise ValueError('Cannot add the point at infitity to itself')

        if P1 == INF_POINT: # P1 == INF_POINT, P2 != INF_POINT
            return P2
        if P2 == INF_POINT: # P1 == INF_POINT, P2 != INF_POINT
            return P1

        x1: int = P1[0]
        y1: int = P1[1]
        x2: int = P2[0]
        y2: int = P2[1]

        # If the x values are the same, and the y values are
        # on equal and opposite sides of the x-axis, the result
        # is the point at infinity. 
        if self.equalModp(x1, x2) and self.equalModp(y1, -y2):
            raise ValueError('Result is point at infinity')

        # If P1 == P2
        if self.equalModp(x1, x2) and self.equalModp(y1, y2):
            # implicit derivation of curve equation
            l: int = self.reduceModp((3 * x1**2 + self.a) * self.inverseModp(2 * y1))
        else:
            l: int = self.reduceModp((y1 - y2) * self.inverseModp(x1 - x2)) # basic slope equation (rise/run)

        v: int = self.reduceModp(y1 - l*x1)
        x3: int = self.reduceModp(l**2 - x1 - x2)
        y3: int = self.reduceModp(-l*x3 - v)

        return (x3, y3) # R

    def multiply(self, k: int, P: tuple[int, int]) -> tuple[int, int]:
        '''Multiplies on the elliptic curve (scalar * point)'''
        Q: tuple[int, int] = INF_POINT

        if k == 0:
            return Q

        while k != 0: # cycling through the bits of k
            if k & 1 != 0: # if lsb is 1
                Q = self.addition(Q, P)
            P = self.addition(P, P)
            k >>= 1 # shift bits to get next lsb

        return Q

    def generateKeyPair(self) -> EllipticCurveKeys:
        '''Generates a cryptographically random public-private
        key pair on th elliptic curve'''
        priv_key: int = secrets.randbits(self.getKeyLength())
        pub_key: tuple[int, int] = self.multiply(priv_key, self.G)
        compressed_pub_key: int = self.compressPoint(pub_key)
        return EllipticCurveKeys(compressed_pub_key, priv_key, self)


    def sign(self, document: bytes, priv_key: int) -> bytes:
        '''ECDSA (Signing): Follows steps from
        https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm'''

        # Step 1: Calculate e = HASH(m), with the output converted to an integer.
        digest: bytes = self.hash(document).digest()
        e: int = intFromBytes(digest)

        # Step 2: Let z be the Ln leftmost bits of e, where Ln is the bit length of the group order n.
        z: int = e & (2**self.n.bit_length() - 1)

        while True:
            k: int
            # Step 3: Select a cryptographically secure random integer k from [1, n-1].
            while (k := secrets.randbelow(self.n)) == 1: # ensures k != 1
                continue

            # Step 4: Calculate the curve point (x1, y1) = k*G
            x1: int = self.multiply(k, self.G)[0]

            # Step 5: Calculate r = x1 mod n. If r = 0, go back to step 3
            r: int = x1 % self.n
            if r == 0:
                continue # go back to step 3

            # Step 6: Calculate s = k^-1 * (z + r*priv_key) mod n. If s = 0, go back to step 3
            inverse_k: int = pow(k, -1, self.n)
            s: int = inverse_k * (z + (priv_key * r) % self.n) % self.n

            if s == 0:
                continue # go back to step 3

            break # else, done
            
        # Append r and s for practical transport reasons
        return r.to_bytes(self.byte_point_length, 'big') + \
                s.to_bytes(self.byte_point_length, 'big')

    def verify(self, signature: bytes, document: bytes, pub_key: tuple[int, int]) -> bool:
        '''ECDSA (Verifying): Follows steps from
        https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm'''

        if self.name in ['Curve25519']:
            raise ValueError('Cannot use Curve25519 for ECDSA')

        # Step 0: Confirm the other's public key is a valid point
        if not self.isPointOnCurve(*pub_key):
            return False
        
        # Step 1: Verify that r and s are integers in [1,n-1]. If not, the signature is invalid.
        r: int = intFromBytes(signature[:self.byte_point_length])
        s: int = intFromBytes(signature[self.byte_point_length:])

        if not (0 < r < self.n and 0 < s < self.n):
            return False

        # Step 2: Calculate e = HASH(m), with the output converted to an integer.
        digest: bytes = self.hash(document).digest()
        e: int = intFromBytes(digest)

        # Step 3: Let z be the Ln leftmost bits of e, where Ln is the bit length of the group order n.
        z: int = e & (2**self.n.bit_length() - 1)

        # Step 4: Calculate u1 = z*s^-1 mod n and u2 = r*s^-1 mod n
        inverse_s: int = pow(s, -1, self.n)
        u1: int = (z * inverse_s) % self.n
        u2: int = (r * inverse_s) % self.n

        # Step 5: Calculate the curve point (x1, y1) = u1*G + u2*pub_key.
        #         If (x1, y1) = point at infinity, the signature is valid
        u1_G: tuple[int, int] = self.multiply(u1, self.G)
        u2_pub_key: tuple[int, int] = self.multiply(u2, pub_key)
        point = self.addition(u1_G, u2_pub_key)

        if point == INF_POINT:
            return True

        # Step 6: The signature is valid if r equiv x1 mod n, invalid otherwise.
        x1: int = point[0]
        return x1 == r % self.n


    def encrypt(self, data: bytes, receiver_pub_key: tuple[int, int]) -> bytes:
        '''Uses ECIES (encryption), as outlined in:
        https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme'''
        
        while True:
            # Step 1: Generate a random number r in [1, n-1] and calculates R = rG
            r: int = secrets.randbelow(self.n)
            if r == 0:
                continue # try again
            R: tuple[int, int] = self.multiply(r, self.G)

            # Step 2: Derive a shared secret S = Px, where P = (Px, Py) = rKb (an P != O)
            S: int = self.multiply(r, receiver_pub_key)[0] # just get x value

            break # r is valid

        # Step 3: Use a KDF to derive a symmetric key k = KDF(S) (don't need MAC key)
        k: bytes = hashlib.pbkdf2_hmac(self.kdf_name, intToBytes(S), b'', 1)

        # Step 4: Encrypt the message c = E(k, m)
        # Step 5: Compute the tag of encrypted message (done inside encrypt function)
        # output = d || c
        d_and_c: bytes = aesEncrypt(data, k, use_multiprocessing=False)

        # Step 6: Return R || d || c
        return R[0].to_bytes(self.byte_point_length, 'big') + \
                R[1].to_bytes(self.byte_point_length, 'big') + \
                d_and_c

    def decrypt(self, input_data, receiver_keys: EllipticCurveKeys) -> bytes:
        '''Uses ECIES (decryption), as outlined in:
        https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme'''

        # Step 0: Seperate the inputs
        R: tuple[int, int] = (intFromBytes(input_data[:self.byte_point_length]), 
                            intFromBytes(input_data[self.byte_point_length:self.byte_point_length*2]))
        c: bytes = input_data[self.byte_point_length*2:] # includes mac
        
        # Step 1: Derive the shared secret S = Px, where P = (Px, Py) = kbR
        # (it is the same as the one Alice derived because P = kbR = kbrG = rkbG = rKb)
        S: int = self.multiply(receiver_keys.private, R)[0] # just get x value

        # Step 2: Derive key the same way the encryptor did: k = KDF(S)
        k: bytes = hashlib.pbkdf2_hmac(self.kdf_name, intToBytes(S), b'', 1)

        # Step 3: Use the MAC to check the tag, procced if d = tag (done inside decrypt)
        # Step 4: Use symmetric decryption scheme to decrypt the message m = E^-1(k, c)
        return aesDecrypt(c, k, use_multiprocessing=False)
        

    def compressPoint(self, point: tuple[int, int]) -> int:
        '''Compresses a point on the elliptic curve'''
        x_bytes: bytes = point[0].to_bytes(self.byte_point_length, 'big')
        prefix: bytes = b'\x02' if point[1] % 2 == 0 else b'\x03'
        return intFromBytes(prefix + x_bytes)

    def decompressPoint(self, compressed_point: int | bytes) -> tuple[int, int]:
        '''Decompresses a compressed point on the elliptic curve'''
        if isinstance(compressed_point, int):
            compressed_point_bytes: bytes = compressed_point.to_bytes(self.byte_point_length+1, 'big')
        else:
            compressed_point_bytes: bytes = compressed_point

        prefix: bytes = bytes([compressed_point_bytes[0]])
        x: int = intFromBytes(compressed_point_bytes[1:]) # ignores the prefix
        y: int = modsqrt(pow(x, 3, self.p) + self.a*x + self.b, self.p)

        if (prefix == b'\x03') == y & 1: # don't really understand this
            return x, y
        return x, self.p - y


    def encodePoint(self, point: tuple[int, int]) -> bytes:
        '''Encodes a point on the curve as bytes'''
        compressed_point: int = self.compressPoint(point)
        return compressed_point.to_bytes(self.cpwps, 'big')

    def decodePoint(self, encoded_point: bytes) -> tuple[int, int]:
        '''Decodes a point of the curve from bytes'''
        return self.decompressPoint(encoded_point)


    # Helper Functions
    def isPointOnCurve(self, x: int, y: int):
        return self.equalModp(y**2, x**3 + self.a*x + self.b)
    
    def discriminant(self) -> int:
        '''Returns the discriminant of the curve'''
        D = -16 * (4*self.a**3 + 27*self.b**2)
        return self.reduceModp(D)

    def getKeyLength(self):
        '''Returns the key length, based on p, the field size'''
        return self.p.bit_length()

    def reduceModp(self, x: int) -> int:
        '''Saves us from using the mod operator. Cleaner'''
        return x % self.p

    def equalModp(self, x: int, y: int) -> bool:
        '''Tests if two given integers are equal mod p'''
        return self.reduceModp(x - y) == 0

    def inverseModp(self, x: int) -> int:
        '''Finds the inverse of the given x mod p'''
        if self.reduceModp(x) == 0:
            raise ValueError('No modular inverse of x mod p')
        return pow(x, -1, self.p)


# Misc Functions
    def convertToFileFormat(self, key_pair: EllipticCurveKeys) -> bytes:
        '''Returns a representation of the compressed public key
        and the private key that can be written to a file.'''
        return key_pair.compressed_public.to_bytes(self.byte_point_length, 'big') + \
            key_pair.private.to_bytes(self.byte_point_length, 'big')


    def convertFromFileFormat(self, byte_rep: bytes) ->  EllipticCurveKeys:
        '''Returns an EllipticCurveKeys object given some
        keys in the file format.'''
        comp_pub: int = intFromBytes(byte_rep[:self.byte_point_length])
        priv: int = intFromBytes(byte_rep[self.byte_point_length:])
        return EllipticCurveKeys(comp_pub, priv, self)

    @staticmethod
    def generateKeysForAllCurves() -> dict[str, dict[str, int]]:
        '''Generates a key pair for each curve detailed in this application.'''
        ec: EllipticCurve
        keys: EllipticCurveKeys
        sizes: list[str] = ['P-224', 'P-256', 'P-384', 'P-521']
        key_dict: dict[str, dict[str, int]] = {}

        # Generate new keys for each size
        for size in sizes:
            ec = EllipticCurve(size)
            keys = ec.generateKeyPair()

            key_dict[size] = {'CompressedPublic': keys.compressed_public, 'Private': keys.private}

        return key_dict




def testing(curve_name: str, print_outcomes: bool = False):
    ec = EllipticCurve(curve_name)
    
    bob_keys = ec.generateKeyPair()
    # print(bob_keys)

    decomp = ec.decompressPoint(bob_keys.compressed_public)
    compression_outcome: bool = bob_keys.public == decomp
    if print_outcomes:
        print(f'Compression Outcome: {compression_outcome}')


    doc: bytes = 'Ben Ross'.encode()
    signature: bytes = ec.sign(doc, bob_keys.private)
    sig_outcome: bool = ec.verify(signature, doc, bob_keys.public)
    if print_outcomes:
        print(f'Signature Valid: {sig_outcome}')
    
    ciphertext: bytes = ec.encrypt(doc, bob_keys.public)
    encrypt_outcome: bool = doc == ec.decrypt(ciphertext, bob_keys)
    if print_outcomes:
        print(f'Encrypt Outcome: {encrypt_outcome}')



    if not print_outcomes:
        assert compression_outcome
        assert sig_outcome
        # assert encrypt_outcome






if __name__ == '__main__':
    from os import system; system('clear')

    no_of_tests = 10
    print('Running Tests... ', end='', flush=True)
    for _ in range(no_of_tests):
        testing('P-256')
    print('Success')
