class KeyGenerationError(BaseException):
    """
    This exception is only raised when an error occours 
    during key generation
    """

class KeyReadError(BaseException):
    """Exception raised when key cannot be read"""

class DecryptionError(BaseException):
    """This exception is raised when decryption fails"""

class VerificationError(BaseException):
    """This exception is raised when signature verfication fails"""

class PaddingError(BaseException):
    """This exception is raised when padding fails"""

