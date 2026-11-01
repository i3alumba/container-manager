class Failure(Exception):
    """Only fixed, non-secret public error codes may cross an API boundary."""

    def __init__(self, code: str, status: int = 503):
        self.code = code
        self.status = status
        super().__init__(code)
