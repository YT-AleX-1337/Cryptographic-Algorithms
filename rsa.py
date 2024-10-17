import secrets
import sys

sys.setrecursionlimit(10000)

prime_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

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

def egcd(a, b): #Returns (gcd(a, b), x, y) where ax + by = gcd(a, b)
    if not a:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def srng(min, max): #Secure Random Number Generator
    return secrets.randbelow(max - min) + min

def is_prime(p):
    for d in prime_list: #Check for small divisors
        if not p % d:
            return 0
    r, d = 0, p - 1
    while not d % 2:
        d //= 2
        r += 1
    for _ in range(32): #Miller-Rabin test. Accuracy is 75%. Since it's being run 32 time, accuracy jumps up to 99.9999999999999999892% (basically 100%)
        a = srng(2, p - 2)
        x = mod_pow(a, d, p)
        if x == 1 or x == p - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                break
        else:
            return 0
    return 1

def generate_prime(min, max): #Generate prime between 2^min and 2^max. There's an infinitesimal chance (but it's still there) that it returns a composite number
    while 1:
        p = srng(2 ** min, 2 ** max) | 1
        if is_prime(p):
            return p

def generate_keypair():
    p = generate_prime(1023, 1024)
    q = generate_prime(1024, 1025)
    n = p * q
    l = (p - 1) * (q - 1)
    if l < 3:
        return generate_keypair()
    e = l
    while egcd(e, l)[0] != 1:
        e = srng(2, l)
    d = egcd(e, l)[1] % l
    return ((e << 2049) + n, (d << 2049) + n) #Pack e and n into a single integer. Same for d and n

def cipher(m, k): #Essentially a relabelled mod_pow function. Used both to encrypt and decrypt integers
    e = k >> 2049 #Unpack e and n from k
    n = k & ((1 << 2049) - 1)
    return mod_pow(m, e, n)

def encrypt(m, k): #Adds random padding to m and encrypts
    m <<= 64
    m += srng(0, 2 ** 64)
    return cipher(m, k)

def decrypt(c, k): #Decrypts and removes the padding to get the original message
    c = cipher(c, k)
    return c >> 64

p, s = generate_keypair()
print(f'PUBLIC:\n{p}\n\nPRIVATE:\n{s}\n')

m = 694201337

print(f'MESSAGE: {m}\n')
c = encrypt(m, p)
print(f'ENCRYPTED MESSAGE:\n{c}\n')  
m = decrypt(c, s)
print(f'DECRYPTED MESSAGE: {m}')
