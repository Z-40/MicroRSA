#  Licensed under the General Public License, Version 3.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.gnu.org/licenses/gpl-3.0.en.html
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""custom exceptions"""


class KeyGenerationError(BaseException):
    """This exception is only raised when an error occurs
    during key generation"""


class KeyReadError(BaseException):
    """Exception raised when key cannot be read"""


class DecryptionError(BaseException):
    """This exception is raised when decryption fails"""


class VerificationError(BaseException):
    """This exception is raised when signature verification fails"""


class PaddingError(BaseException):
    """This exception is raised when padding fails"""


class PrimeGenerationError(BaseException):
    """This exception is raised when prime generation fails"""
