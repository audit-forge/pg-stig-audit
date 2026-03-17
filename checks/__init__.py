from .config import ConfigChecker
from .logging import LoggingChecker
from .auth import AuthChecker
from .privileges import PrivilegesChecker

ALL_CHECKERS = [ConfigChecker, LoggingChecker, AuthChecker, PrivilegesChecker]
