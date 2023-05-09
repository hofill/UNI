import utils
from Certainty import Certainty


class BCState:
    def __init__(self):
        self.__certainty = Certainty()
        self.__modified = False
        self.__category = None  # ECB, CBC, ECB_CBC or Stream
        self.__past_combos = []

    def add_combo(self, combo: (bytes, bytes), plaintext: str):
        self.__past_combos.append((combo, plaintext))

    def check_combo(self, combo: (bytes, bytes), plaintext: str):
        if self.__category is None:
            # Try to determine the category
            self.check_ecb(combo)

    def check_ecb(self, combo):
        if len(self.__past_combos) == 1:
            # If there is only one combo, we can't confidently determine the category, but we can make a guess
            if combo[0] is None:
                # If the combo has no IV, it is likely ECB
                self.__category = 'ECB'
            else if combo[0] is not None:
                # If the combo has an IV, it is likely CBC
                self.__category = 'CBC'
            return

    def check_combo_no_plaintext(self, combo: (bytes, bytes)):
        iv, blocks = combo

        blocks = list(utils.chunks(blocks, utils.BLOCK_SIZE))

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
            probabilities['CFB'] = .1
            probabilities['CTR'] = .1
            probabilities['OFB'] = .1

        self.__certainty.normalize(probabilities)

        # Modified only if function succeeds
        if probabilities != utils.default_probabilities:
            self.__modified = True

    def is_modified(self):
        return self.__modified

    def __check_block_size(self):
        pass

    def check_ecb(self):
        pass
