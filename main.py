from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex("964d3bf6aaafe958b3a36bd33a48d5ae")
iv = bytes.fromhex("964d3bf6aaafe958b3a36bd33a48d5ae")  # not recommended

BLOCK_SIZE = 16
m = b"bob and alice are together now"


def get_certainty(certainty):
    if certainty == 0:
        return "Certainly not"
    if certainty < 0.1:
        return "Probably not"
    if certainty < 0.5:
        return "Maybe"
    if certainty < 0.8:
        return "Probably"
    if certainty == 1:
        return "Surely"


def encrypt_with_mode(mode_of_operation, message, iv=None):
    if iv:
        a = AES.new(key, mode_of_operation, iv=iv)
    else:
        a = AES.new(key, mode_of_operation)
    return iv, a.encrypt(message)


def check_stream(data):
    certainty = 0
    if data[0] is None:
        certainty += 0.3
    l = len(data[1]) / BLOCK_SIZE
    if l == int(l):
        certainty += 0.7
    return certainty


if __name__ == "__main__":
    print(m)
    cbc = encrypt_with_mode(AES.MODE_CBC, pad(m, BLOCK_SIZE), iv=iv)
    ecb = encrypt_with_mode(AES.MODE_ECB, pad(m, BLOCK_SIZE))
    ctr = encrypt_with_mode(AES.MODE_CTR, m)

    # Check if encryption method is a stream method
    print(get_certainty(check_stream(ecb)))
