#!/usr/bin/env python3
import os

from Crypto.Cipher import AES

KEY = os.urandom(16)
nonce = os.urandom(8)


def encrypt_data():
    aes = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    data = bytes.fromhex(input("Data (HEX): ").strip())
    encrypted = aes.encrypt(data)
    print(nonce.hex() + encrypted.hex())


def decrypt_data():
    aes = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    data = bytes.fromhex(input("Data (HEX): ").strip()[32:])
    print(aes.decrypt(data).hex())


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
