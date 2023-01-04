from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from BCDetector import BCDetector

key = bytes.fromhex("964d3bf6aaafe958b3a36bd33a48d5ae")
iv = bytes.fromhex("964d3bf6aaafe958b3a36bd33a48d5ae")  # not recommended

BLOCK_SIZE = 16
m = b"bob and alice are together now"


def check_stream(data):
    certainty = 0
    if data[0] is None:
        certainty += 0.3
    l = len(data[1]) / BLOCK_SIZE
    if l == int(l):
        certainty += 0.7
    return certainty


if __name__ == "__main__":
    detector = BCDetector()
    detector.analyse_string()
    pass
