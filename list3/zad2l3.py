import math
import random
from sympy import randprime
import hashlib

def egcd(a, b):
    # Extended Euclidean Algorithm
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    # Modular Inverse using Extended Euclidean Algorithm
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def randomZnElement(N):
    # Returns a random element in Z_N^*
    g = N
    while math.gcd(g, N) != 1:
        g = random.randint(2, N)
    return g


def GenModulus(w):
    # Generates RSA modulus N of bit-length w
    n = len(w) // 2
    p = randprime(2 ** n, 2 ** (n+1))
    q = randprime(2 ** n, 2 ** (n+1))
    N = p * q
    return N, p, q

def GenRSA(w):
    # Generates RSA keys of bit-length w
    n = len(w)
    N, p, q = GenModulus(w)
    m = (p-1) * (q-1)
    e = 2 ** 16 + 1
    d = modinv(e, m)
    return N, e, d, p, q


def check(n, x, a, e, b):
    # Static method to check the verification step
    left = (b ** 2) % n
    right = (a * (x ** e)) % n
    return left == right

def sha512_first_x_bits_as_list(data: bytes, x: int) -> list:
    digest = hashlib.sha512(data).digest()            # 64 bytes = 512 bits
    bitstr = ''.join(f'{b:08b}' for b in digest)      # big-endian bit order per byte
    first100 = bitstr[:x]                           # first 100 characters '0'/'1'
    return [int(b) for b in first100]

class FSI_Prover:
    # Fiat-Shamir Identification Prover
    def __init__(self, w, m):
        self.w = w
        self.m = m
        self.len = 10
        self.GenFSI(w)
        self.r = None
        self.a = None
        self.b = None


    def get_public_key(self):
        return self.n, self.x

    def GenFSI(self, w):
        # Generates keys for Fiat-Shamir Identification
        self.n, _, _, p, q = GenRSA(self.w)
        self.y = randomZnElement(self.n) # secret key
        self.x = (self.y ** 2) % self.n # public key


    def FSI_Prover_Step_1_Commit(self):
        self.r = [randomZnElement(self.n) for _ in range(self.len)]
        a = [((r ** 2) % self.n) for r in self.r]
        # a = (self.r ** 2 * modinv(self.x, self.n)) % self.n if dishonest
        bits = sha512_first_x_bits_as_list(self.m + b''.join([(x %  100).to_bytes() for x in a]), self.len)
        y = [(self.r[i] * (self.y**int(bits[i]))) % self.n for i in range(len(self.r))]
        return a, y


class FSI_Verifier:
    # Fiat-Shamir Identification Verifier

    def __init__(self, n, x, m):
        # Initializes the verifier with public key (n, x)
        self.n = n
        self.x = x
        self.m = m
        self.len = 10
        self.e = None
        self.a = None
        self.b = None

    def FSI_Verifier_Step_1_Challenge(self, a, y):
        # Verifier's challenge in Fiat-Shamir Identification
        e = sha512_first_x_bits_as_list(self.m + b''.join([(x %  100).to_bytes() for x in a]), self.len)
        for i in range(len(y)):
            left = (y[i] ** 2) % self.n
            right = (a[i] * (self.x**int(e[i]))) % self.n
            if left != right:
                print(i)
                return False
        return True



class FSI:
    # Fiat-Shamir Identification Protocol

    def __init__(self, w, rounds=4):
        # Initializes the protocol with bit-length w and number of rounds
        self.w = w
        self.rounds = rounds

    def run(self):
        # Runs the Fiat-Shamir Identification protocol

        message = b"kinda nice"
        self.prover = FSI_Prover(self.w, message)

        n, x = self.prover.get_public_key()
        print(f"Public key (n, x): ({n}, {x})\n")

        self.verifier = FSI_Verifier(n, x, message)

        fsi = {"public_key": (n, x), "rounds": self.rounds, "transcript": []}
        transcript = []

        a, y = self.prover.FSI_Prover_Step_1_Commit()
        print(f"Prover sends a: {a}\ny: {y}")

        # Verifier's challenge
        if self.verifier.FSI_Verifier_Step_1_Challenge(a, y):
            print("Verification successful!\n")
        else:
            print("Verification failed!\n")

        return


xd = FSI("1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
xd.run()
"""
    tutaj trudność ataku polga na tym że aby ustawic podpis a trzeba jednocześnie ustawić  a na odwrotność x oraz aby hash z tego miał odpowiedni bit na tym miejscu
"""