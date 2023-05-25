from Certainty import Certainty


class BCState:
    """
    Class that holds the state of the detector
    """

    def __init__(self):
        self.__certainty = Certainty()
        self.__modified = False
        self.__category = None  # ECB, CBC, ECB_CBC or Stream
        self.__block_size = None
        self.__provides_iv = False
        self.__past_combos = []

    def add_combo(self, combo: (bytes, bytes), plaintext: str):
        self.__past_combos.append((combo, plaintext))

    def check_combo(self, combo: (bytes, bytes), plaintext: str):
        if self.__category is None:
            # Try to determine the category
            self.check_ecb(combo)

    def check_ecb(self, combo: (bytes, bytes)):
        if len(self.__past_combos) == 1:
            # If there is only one combo, we can't confidently determine the category, but we can make a guess
            if combo[0] is None:
                # If the combo has no IV, it is likely ECB
                self.__category = 'ECB'
            elif combo[0] is not None:
                # If the combo has an IV, it is likely CBC
                self.__category = 'CBC'
            return

    def check_combo_no_plaintext(self, combo: (bytes, bytes)):
        pass

    def is_modified(self):
        return self.__modified

    def check_block_size(self, ciphertext, plaintext):
        """
        Checks the block size of the cipher using many encryption/decryption combos

        :param ciphertext: The ciphertext
        :param plaintext: The plaintext that was encrypted to get the ciphertext
        :return:
        """
        if len(plaintext) == 1:
            # If the plaintext is only one byte, there are three possibilities:
            # 1. The ciphertext's length is 1, meaning the block size is 1, which is a Stream type cipher
            #
            # 2. The ciphertext's length is 17, meaning the block size is 1,
            #    but we also get the IV which is also a Stream type cipher
            #
            # 3. The ciphertext's length is something else, meaning further analysis is required
            if len(ciphertext) == 1:
                self.__category = 'Stream'
                self.__block_size = 1
                return True
            elif len(ciphertext) == 17:
                self.__category = 'Stream'
                self.__block_size = 1
                self.__provides_iv = True
                return True
            return False
        if len(plaintext) == 16:
            # If the plaintext is 16 bytes, there are three possibilities:
            # 1. The ciphertext's length is 16, meaning the block size is 16, which is an ECB type cipher
            #
            # 2. The ciphertext's length is 32, meaning the block size is either 16 and we get the IV, or
            #    the block size is 32, and we don't get the IV, which is an ECB_CBC type cipher
            #
            # 3. The ciphertext's length is something else, meaning further analysis is required
            if len(ciphertext) == 16:
                self.__category = 'ECB'
                self.__block_size = 16
                return True
            elif len(ciphertext) == 32:
                self.__category = 'ECB_CBC'
                return False
            return False

    def check_block_size_heavy(self, ciphertext, plaintext):
        pass
