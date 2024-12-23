
class Target:

    tlsv1_2: bool = None
    tlsv1: bool = None

    def __init__(self, remote: str, port: int, method_port: int) -> None:
        self.remote = remote
        self.port = port
        self.method_port = method_port

    def use_tls(self) -> bool:
        return self.tlsv1_2 or self.tlsv1
