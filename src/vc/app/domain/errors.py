class DomainError(Exception):
    pass


class DocumentNotConfirmed(DomainError):
    pass


class InvalidChallenge(DomainError):
    pass


class KeyExpired(DomainError):
    pass
