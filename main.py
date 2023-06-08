from BCDetector import BCDetector
from pwn import *

from exceptions import BadPaddingException

context.log_level = 'critical'


class Det(BCDetector):
    def __init__(self):
        super().__init__(max_retries=3, save_to_file=True, server=True)

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
        server.recvuntil(b"> ")
        server.sendline(b"1")
        server.sendline(data.encode())
        return server.readline().strip().split(b": ")[1].decode()

    def init_server(self):
        r = process(["./test_servers/ecb.py"])
        return r


if __name__ == "__main__":
    detector = Det()
    detector.begin()
    pass
