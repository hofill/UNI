import utils


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

    def print_certainty(self):
        sorted_certainties = {k: v for k, v in sorted(self.__certainty.items(), reverse=True, key=lambda item: item[1])}
        print(f"{utils.Color.BOLD + utils.Color.BLUE}======= Probabilities ======={utils.Color.END}")
        for block_cipher_mode, percentage in sorted_certainties.items():

            print(f"{utils.calculate_color(percentage)}{block_cipher_mode}{utils.Color.END}: {round(percentage * 100, 3)}%")
        print(f"{utils.Color.BOLD + utils.Color.BLUE}============================={utils.Color.END}")

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
        self.print_certainty()
