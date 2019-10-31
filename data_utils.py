def hexToDec(hex: str) -> list:
    bArr = bytearray.fromhex(hex)
    return [x for x in bArr]

def decToHex(dec: list) -> str:
    return ''.join('{:02x}'.format(x) for x in dec)
