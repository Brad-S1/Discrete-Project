from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
import Crypto
import sys

# Check for Crypto package's version
"""if Crypto.__version__ < '3.9.9':
    print(
        "Warning: This implementation requires PyCryptodome version 3.9.9 or newer")
    sys.exit()"""


def gcd(a, b):
    """Calculate the Greatest Common Divisor of a and b."""
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, phi):
    """Find the multiplicative inverse of e modulo phi."""
    # Extended Euclidean Algorithm
    d_old = 0;
    r_old = phi
    d_new = 1;
    r_new = e
    while r_new > 0:
        quotient = r_old // r_new
        (d_old, d_new) = (d_new, d_old - quotient * d_new)
        (r_old, r_new) = (r_new, r_old - quotient * r_new)
    return d_old % phi


def generate_keypair(keysize):
    """Generate an RSA keypair with a given keysize"""
    e = d = N = 0

    # Step 1: Choose two prime numbers
    p = getPrime(keysize)
    q = getPrime(keysize)

    # Step 2: Compute N = pq
    N = p * q

    # Step 3: Compute the totient of N
    phi = (p - 1) * (q - 1)

    # Step 4: Select e
    # e must be coprime to phi and smaller than phi
    e = 65537
    while gcd(e, phi) != 1:
        e = getPrime(keysize // 2)

    # Step 5: Calculate d
    d = multiplicative_inverse(e, phi)

    # The public key is (e, N) and the private key is (d, N)
    return ((e, N), (d, N))


def encrypt(pk, plaintext):
    """Encrypt a message with a public key"""
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher


def decrypt(pk, ciphertext):
    """Decrypt a message with a private key"""
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)


if __name__ == '__main__':
    print("RSA Encrypter/ Decrypter")
    keysize = int(input("Enter key size (e.g., 1024): "))

    public, private = generate_keypair(keysize)
    print("Your public key is ", public, " and your private key is ", private)

    message = input("Enter a message to encrypt: ")
    encrypted_msg = encrypt(public, message)
    print("Your encrypted message is: ")
    print(''.join(map(lambda x: str(x), encrypted_msg)))

    print("Decrypting message with private key ", private, " . . .")
    print("Your message is:")
    print(decrypt(private, encrypted_msg))
