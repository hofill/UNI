import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex("964d3bf6aaafe958b3a36bd33a48d5ae")
iv = bytes.fromhex("964d3bf6aaafe958b3a36bd33a48d5ae")

m = b"bob and alice are together now"


def encrypt_with_mode(mode_of_operation, message, iv=None):
    if iv:
        a = AES.new(key, mode_of_operation, iv=iv)
    else:
        a = AES.new(key, mode_of_operation)
    return iv, a.encrypt(message)


if __name__ == "__main__":
    print(m)
    print(encrypt_with_mode(AES.MODE_CBC, pad(m, 16), iv=iv))
    print(encrypt_with_mode(AES.MODE_CTR, m))
