"""Minimal DER encoder for the test helper test_fake_attestation.py (no dependencies)."""

def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag_byte_or_bytes, content):
    t = bytes([tag_byte_or_bytes]) if isinstance(tag_byte_or_bytes, int) else tag_byte_or_bytes
    return t + _len(len(content)) + content


def seq(*parts): return tlv(0x30, b"".join(parts))
def set_(*parts): return tlv(0x31, b"".join(sorted(parts)))
def integer(v): return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))
def enum(v): return tlv(0x0A, v.to_bytes(1, "big"))
def octets(b): return tlv(0x04, b)
def boolean(v): return tlv(0x01, b"\xff" if v else b"\x00")
def null(): return b"\x05\x00"


def explicit(n, inner):
    """[n] EXPLICIT, context-specific, constructed (high-tag-number form when n >= 31)."""
    if n < 31:
        tag = bytes([0xA0 | n])
    else:
        groups = []
        while True:
            groups.insert(0, n & 0x7F)
            n >>= 7
            if not n:
                break
        tag = bytes([0xBF]) + bytes(g | 0x80 for g in groups[:-1]) + bytes([groups[-1]])
    return tlv(tag, inner)
