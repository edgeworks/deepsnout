"""Offline domain boundaries and bounded approximate diversity."""
import base64
import ctypes
import ctypes.util
import hashlib
import math

_PSL, _CONTEXT = None, None
try:
    name = ctypes.util.find_library("psl")
    if name:
        _PSL = ctypes.CDLL(name)
        _PSL.psl_builtin.restype = ctypes.c_void_p
        _PSL.psl_registrable_domain.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _PSL.psl_registrable_domain.restype = ctypes.c_char_p
        _CONTEXT = _PSL.psl_builtin()
except (OSError, AttributeError):
    _PSL = None


def psl_available():
    return bool(_PSL and _CONTEXT)


def service_group(domain):
    domain = domain.lower().rstrip(".")
    if psl_available():
        result = _PSL.psl_registrable_domain(_CONTEXT, domain.encode("idna"))
        if result:
            return result.decode("ascii")
    # Never guess by taking the final two labels; preserve exact name instead.
    return domain


class Diversity:
    """256-register HyperLogLog (about 6.5% standard error), not forensic counts."""
    def __init__(self, encoded=""):
        self.registers = bytearray(base64.b64decode(encoded)) if encoded else bytearray(256)
        if len(self.registers) != 256:
            raise ValueError("Invalid diversity sketch")

    def add(self, value):
        h = int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big")
        bucket, remaining = h >> 56, h & ((1 << 56) - 1)
        rank = 57 - remaining.bit_length()
        self.registers[bucket] = max(self.registers[bucket], rank)

    def estimate(self):
        m = 256
        estimate = (0.7213 / (1 + 1.079 / m)) * m * m / sum(2.0 ** -v for v in self.registers)
        zero = self.registers.count(0)
        if zero and estimate <= 2.5 * m:
            estimate = m * math.log(m / zero)
        return max(0, round(estimate))

    def encode(self):
        return base64.b64encode(self.registers).decode("ascii")
