from BCState import BCState
from utils import convert_to_bytes


class BadPaddingException(Exception):
    """
    Raised when the padding is incorrect
    """


class BCDetector:
    """
    Base class for all detectors. This class should be inherited from and the
    `analyse_server`, `encrypt` and `decrypt` methods should be implemented.

    The `begin` method should be called to start the detector. The analyse_server
    method should return a process object that is used to communicate with the server,
    which will be passed to the encrypt and decrypt method.

    :param max_retries: The maximum number of times to retry an operation
    :param save_to_file: Whether to save the results to a file
    :param server: Whether to use a server to decrypt the data
    """

    def __init__(self, **kwargs):
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.save_to_file = bool(kwargs.get('save_to_file', False))
        self.server = bool(kwargs.get('server', False))
        self.state = BCState()
        self.attempts = 0
        self.history = []

    def encrypt(self, data, server):
        """
        Unimplemented method that should encrypt the data using the server.

        :param data: The data to encrypt, as bytes
        :param server: The server to use
        :return: The encrypted data as bytes (decoded from hex) or a string (hex or base64)
        """
        raise NotImplementedError

    def decrypt(self, data, server):
        """
        Unimplemented method that should decrypt the data using the server.

        :param data: The data to decrypt, as bytes
        :param server: The server to use
        :return: The decrypted data as bytes (decoded from hex) or a string (hex or base64)
        """
        raise NotImplementedError

    def init_server(self):
        raise NotImplementedError

    def begin(self):
        """
        Starts the detector. This method should be called after the detector has been
        initialized. This method will call the `analyse_server` method to get the server
        object, then call the `detect` method to start the detection process. If the
        init_server method is not implemented, it will exit with an error.

        If the `save_to_file` parameter is set, the results will be saved to a file.


        :return: None
        """
        try:
            server = self.init_server()
        except NotImplementedError:
            print("ERROR: init_server method not implemented")
            return None
        # Check 3 base encrypted strings to determine ECB, CBC, ECB_CBC or Stream
        l_1 = convert_to_bytes(self.encrypt(b"\x00" * 15, server))
        l_2 = convert_to_bytes(self.encrypt(b"\x00" * 32, server))
        l_3 = convert_to_bytes(self.encrypt(b"\x00" * 33, server))
        self.analyse_string(l_1)
        self.analyse_string(l_2)
        self.analyse_string(l_3)

    def analyse_string(self, data, plaintext=None, iv=None):
        if plaintext is not None:
            self.state.check_combo((iv, data), plaintext)
        else:
            self.state.check_combo_no_plaintext((iv, data))
