from BCState import BCState


class BCDetector:
    def __init__(self, **kwargs):
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.save_to_file = bool(kwargs.get('save_to_file', False))
        self.server = bool(kwargs.get('server', False))
        self.state = BCState()
        self.attempts = 0
        self.history = []

    def encrypt(self):
        raise NotImplementedError

    def decrypt(self):
        raise NotImplementedError

    def analyse_server(self):
        pass

    def analyse_string(self):
        pass
