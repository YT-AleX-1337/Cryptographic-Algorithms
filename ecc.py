import secrets
import sys

sys.setrecursionlimit(10000) 

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):
        return f'({self.x}, {self.y})'

    def __eq__(p1, p2):
        return p1.x == p2.x and p1.y == p2.y
    
    def __neg__(self):
        return Point(self.x, -self.y)
    
    def __add__(p1, p2):
        if p2 is None:
            return p1
        if p1 == -p2:
            return None #The sum of a point and its inverse is point O (aka infinity, aka None)
        if p1 == p2:
            return p1.double()
        l = (p2.y - p1.y) * mod_pow(p2.x - p1.x, P - 2, P) % P
        sx = (l ** 2 - p1.x - p2.x) % P
        return Point(sx, (l * (p1.x - sx) - p1.y) % P) 
        
    def __sub__(p1, p2):
        return p1 + (-p2)
    
    def __mul__(self, n): #Multiplication uses the 'double and add' method
        result = None
        addend = self
        while n:
            if n & 1:
                result += addend
            addend = addend.double()
            n >>= 1
        return result 
    
    def __radd__(p1, p2):
        return p1 + p2
    
    def __rmul__(self, n):
        return self * n
    
    def double(self):
        l = (3 * self.x ** 2 + A) * mod_pow(2 * self.y, P - 2, P) % P
        sx = (l ** 2 - 2 * self.x) % P 
        return Point(sx, (l * (self.x - sx) - self.y) % P)

def pack(p): #Pack point into a single integer
    ly = p.y.bit_length()
    return (p.x << ly + 10) + (p.y << 10) + ly

def unpack(p): #Unpack point from integer
    ly = p & ((1 << 10) - 1)
    return Point(p >> ly + 10, (p & ((1 << ly + 10) - 1)) >> 10)

#Elliptic curve used is SECP256K1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A, B = 0, 7

def mod_pow(a, b, m): #a^b mod m
    c = 1
    while b > 0:
        a %= m
        if b % 2:
            c *= a
            c %= m
        b >>= 1
        a **= 2
    return c % m

def srng(min, max): #Secure Random Number Generator
    return secrets.randbelow(max - min) + min

def generate_keypair():
    s = srng(1, N)
    p = G * s
    return pack(p), s           
    
def encrypt(m, p):
    p = unpack(p)
    n = srng(1, N) #Random nonce
    c1 = pack(G * n)
    c2 = pack(p * n + Point(m, 0))
    return pack(Point(c1, c2)) #Point(c1, c2) is not a point on the elliptic curve, this is done only to pack c1 and c2 into a single integer c

def decrypt(c, s):
    c = unpack(c)
    c1, c2 = unpack(c.x), unpack(c.y)
    return (c2 - c1 * s).x

p, s = generate_keypair()
print(f'PUBLIC:\n{p}\n\nPRIVATE:\n{s}\n')

m = 1337 #Message can be any number between 0 and P - 1

print(f'MESSAGE: {m}\n')
c = encrypt(m, p)
print(f'ENCRYPTED MESSAGE:\n{c}\n')  
m = decrypt(c, s)
print(f'DECRYPTED MESSAGE: {m}')
