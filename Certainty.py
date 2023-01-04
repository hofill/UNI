class Certainty:
    def __init__(self, certainty=0):
        self.__round = 0
        self.__certainty = {
            "ECB": certainty,
            "CBC": certainty,
            "CFB": certainty,
            "OFB": certainty,
            "CTR": certainty,
        }

    def get_certainty_string(self, bctype: str):
        if self.__certainty[bctype] == 0:
            return "Certainly not"
        if self.__certainty[bctype] < 0.1:
            return "Probably not"
        if self.__certainty[bctype] < 0.5:
            return "Maybe"
        if self.__certainty[bctype] < 0.8:
            return "Probably"
        if self.__certainty[bctype] == 1:
            return "Surely"

    def get_certainty(self):
        return self.__certainty

    def increase_round(self):
        self.__round += 1

    def normalize(self, probabilities: dict):
        total = sum(probabilities.values())
        for key in self.__certainty:
            self.__certainty[key] += probabilities[key] / total
        total = sum(self.__certainty.values())
        self.__certainty = {key: value / total for key, value in self.__certainty.items()}
