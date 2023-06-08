#!/usr/bin/env python3
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = os.urandom(16)
IV = os.urandom(16)
BLOCK_SIZE = 16


def encrypt_data():
    aes = AES.new(KEY, AES.MODE_CBC, iv=IV)
    data = pad(bytes.fromhex(input("Data (HEX): ").strip()), BLOCK_SIZE)
    encrypted = aes.encrypt(data)
    print(IV.hex() + encrypted.hex())


def decrypt_data():
    aes = AES.new(KEY, AES.MODE_CBC, iv=IV)
    data = bytes.fromhex(input("Data (HEX): ").strip()[32:])
    print(unpad(aes.decrypt(data), BLOCK_SIZE).hex())


if __name__ == "__main__":
    functions = {
        "1": encrypt_data,
        "2": decrypt_data
    }

    options = """
    1. Encrypt Data
    2. Decrypt Data
    q. Quit"""

    while True:
        print(options)
        option = input("> ")
        try:
            if option not in functions.keys():
                quit()
            functions[option]()
        except Exception as e:
            print(e)
