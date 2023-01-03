from Certainty import Certainty


class BCState:
    def __init__(self):
        self.__certainty = Certainty()
        self.__modified = False

    def check_combo(self, combo: (bytes, bytes)):
        pass

    def is_modified(self):
        return self.__modified
