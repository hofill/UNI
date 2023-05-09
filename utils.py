import base64
import string

BLOCK_SIZE = 16

default_probabilities = {
    "ECB": 0,
    "CBC": 0,
    "CFB": 0,
    "OFB": 0,
    "CTR": 0,
}


def chunks(lst, n):
    """Yield successive n-sized chunks from list."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def calculate_color(amt):
    if amt <= .3:
        return Color.RED
    if amt <= .6:
        return Color.YELLOW
    if amt <= .8:
        return Color.GREEN
    else:
        return Color.GREEN + Color.BOLD

def convert_to_bytes(data):
    if type(data) == str:
        # detect if string is hex
        if len(data) % 2 == 0 and all(c in string.hexdigits for c in data):
            return bytes.fromhex(data)
        # else if data is base64
        elif len(data) % 4 == 0 and all(c in string.ascii_letters + string.digits + "+/=" for c in data):
            return base64.b64decode(data)
    elif type(data) == bytes:
        return data
    else:
        raise TypeError("Data must be either a string or bytes")