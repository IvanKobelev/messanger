class InternalException(Exception):

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message


class BadRequestException(InternalException):

    pass


class UnauthorizedException(InternalException):

    pass
