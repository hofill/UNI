from BCDetector import BCDetector, BadPaddingException
from pwn import *


class Det(BCDetector):
    def decrypt(self, data, server: process):
        server.clean(0.1)
        server.sendline(b"2")
        server.sendline(data.hex().encode())
        answer = server.readline().strip()
        if b"Padding is incorrect." in answer:
            return BadPaddingException
        else:
            return answer

    def encrypt(self, data, server: process):
        server.recvuntil("> ")
        server.sendline(b"1")
        server.sendline(data.hex().encode())
        return server.readline().strip().split(b": ")[1].decode()

    def init_server(self):
        r = process(["./test_servers/cbc.py"])
        return r


if __name__ == "__main__":
    detector = Det()
    detector.begin()
    pass
