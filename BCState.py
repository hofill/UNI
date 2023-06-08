from Certainty import Certainty
from exceptions import BlockSizeUnidentifiableException


class BCState:
    """
    Class that holds the state of the detector
    """

    def __init__(self):
        """
        Initialises the state

        step - The step of the detector:
        0: Detecting the block size
        1: Detecting the padding method
        2: Detecting the block cipher mode
        """
        self.__certainty = Certainty()
        self.__category = None  # ECB, CBC, ECB_CBC or Stream
        self.__detected_block_cipher_mode = None  # ECB, CBC, CFB, OFB and CTR

        self.__block_size = None
        self.__block_size_combo_history = []

        self.__padding_method = None  # PKCS7, None, Block, Block+
        self.__padding_method_combo_history = []

        self.__provides_iv = False
        self.__past_combos = []
        self.__step = 0

    def initialize_no_server(self):
        self.__block_size = 16
        self.__padding_method = 'PKCS7'

    def add_combo(self, combo: str, plaintext: str):
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

    def add_block_size_check(self, plaintext_length, ciphertext):
        """
        Checks the block size of the cipher using many encryption/decryption combos

        :param plaintext_length: The plaintext that was encrypted to get the ciphertext's length
        :param ciphertext: The ciphertext
        :return: True if more checks are needed, False if the block size has been determined
        """
        ciphertext = bytes.fromhex(ciphertext)
        self.__block_size_combo_history.append((plaintext_length, ciphertext))
        if len(self.__block_size_combo_history) == 1:
            return True

        # Compare the new ciphertext to the old ciphertext
        previous_combo = self.__block_size_combo_history[len(self.__block_size_combo_history) - 2]
        old_ciphertext = previous_combo[1]
        if len(ciphertext) == len(old_ciphertext):
            return True
        elif len(ciphertext) + 1 == len(old_ciphertext):
            # The block size is 1
            self.__block_size = 1
            self.__category = 'Stream'
            self.__padding_method = 'None'
            return False
        elif len(ciphertext) + 1 > len(old_ciphertext):
            # The block size is the difference between the two lengths
            self.__block_size = len(ciphertext) - len(old_ciphertext)
            self.__category = 'ECB_CBC'
            return False
        else:
            raise BlockSizeUnidentifiableException("The block size is not findable")

    def check_padding(self, plaintext, ciphertext):
        """
        Checks the padding method of the cipher using many encryption/decryption combos

        :param plaintext: The plaintext that was encrypted to get the ciphertext
        :param ciphertext: The ciphertext
        :return: True if more checks are needed, False if the padding method has been determined
        """
        if self.__block_size is None:
            return False

        if self.__block_size == 1:
            self.__padding_method = 'None'
            return True

        if self.__padding_method is not None:
            return False
        self.__padding_method_combo_history.append((plaintext, ciphertext))
        if len(self.__padding_method_combo_history) == 1:
            return True

        # Compare the new ciphertext to the old ciphertext
        previous_combo = self.__padding_method_combo_history[len(self.__padding_method_combo_history) - 2]
        old_plaintext = previous_combo[0]
        old_ciphertext = previous_combo[1]

    def check_padding_method_determinable(self, encrypt_method):
        """
        Checks if the padding method can be determined

        :return: True if the padding method can be determined, False otherwise
        """
        # The padding method can be determined if
        # 1. The block size is known
        # 2. There is no message concatenated to the plaintext
        # 3. If there is a message concatenated to the plaintext, that message is known or is a multiple of the block
        # size

        if self.__block_size is None:
            return True

        to_encrypt = b'A' * (self.__block_size - 1)
        ciphertext_full_minus_one = bytes.fromhex(encrypt_method(to_encrypt.hex()))
        ciphertext_full = bytes.fromhex(encrypt_method((to_encrypt + b'A').hex()))
        if len(ciphertext_full) == len(ciphertext_full_minus_one):
            return False
        else:
            return True

    def get_block_size(self):
        return self.__block_size

    def get_padding_method(self):
        return self.__padding_method

    def get_block_cipher_mode_category(self):
        return self.__category

    def get_block_cipher_mode(self):
        return self.__detected_block_cipher_mode
