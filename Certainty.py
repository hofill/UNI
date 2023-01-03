class Certainty:
    def __init__(self, certainty=0):
        self.certainty = certainty

    def get_certainty_string(self):
        if self.certainty == 0:
            return "Certainly not"
        if self.certainty < 0.1:
            return "Probably not"
        if self.certainty < 0.5:
            return "Maybe"
        if self.certainty < 0.8:
            return "Probably"
        if self.certainty == 1:
            return "Surely"
