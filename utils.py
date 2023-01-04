BLOCK_SIZE = 16

default_probabilities = {
    "ECB": 0,
    "CBC": 0,
    "CFB": 0,
    "OFB": 0,
    "CTR": 0,
}


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
