class CAPWAPFuzzerError(Exception):
    """Base class for all CAPWAP Discovery Fuzzer errors."""
    pass


class NoResponseError(CAPWAPFuzzerError):
    def __init__(
        self,
        message: str,
        ac_ip: str | None = None,
        ac_port: int | None = None,
        timeout: float | None = None,
    ):
        super().__init__(message)
        self.ac_ip = ac_ip
        self.ac_port = ac_port
        self.timeout = timeout


class InvalidResponseError(CAPWAPFuzzerError):
    def __init__(self, message: str, raw_data: bytes | None = None):
        super().__init__(message)
        self.raw_data = raw_data
