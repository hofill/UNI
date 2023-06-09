from attacks.Attack import Attack


class ChosenPlaintextAttack(Attack):
    def run(self):
        self.__encrypt("A" * 16)
        pass
