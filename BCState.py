import utils
from Certainty import Certainty


class BCState:
    def __init__(self):
        self.__certainty = Certainty()
        self.__modified = False

    def check_combo(self, combo: (bytes, bytes), plaintext: str):
        pass

    def check_combo_no_plaintext(self, combo: (bytes, bytes)):
        iv, blocks = combo

        blocks = list(utils.chunks(blocks, utils.BLOCK_SIZE))
        print(blocks)

        # Calculate the probability that the blocks were encrypted using each mode
        probabilities = utils.default_probabilities

        if iv is not None:
            probabilities['CBC'] += .25
            probabilities['CFB'] += .25
            probabilities['CTR'] += .25
            probabilities['OFB'] += .25
        else:
            probabilities['ECB'] = 1
            self.__certainty.normalize(probabilities)
            return

        if len(blocks[-1]) % utils.BLOCK_SIZE != 0:
            probabilities['CBC'] = 0
            probabilities['CFB'] += .33
            probabilities['CTR'] += .33
            probabilities['OFB'] += .33
        else:
            probabilities['CBC'] += .7

        self.__certainty.normalize(probabilities)

        # Modified only if function succeeds
        if probabilities != utils.default_probabilities:
            self.__modified = True

    def is_modified(self):
        return self.__modified
