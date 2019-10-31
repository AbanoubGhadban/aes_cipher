import aes_constants as const
from data_utils import *

def subBytes(bytes: list) -> list:
    newBytes = []
    for b in bytes:
        newBytes.append(const.S_BOX[b])
    return newBytes

def invSubBytes(bytes: list) -> list:
    invBytes = []
    for b in bytes:
        invBytes.append(const.S_BOX_INV[b])
    return invBytes

def xorMatrix(m1: list, m2: list) -> list:
    assert len(m1)==len(m2), "Two lists must have the same length"
    m = []
    for i1, i2 in zip(m1, m2):
        m.append(i1^i2)
    return m

def shiftRows(state: list) -> list:
    assert len(state)==16, "State length must be 16 bytes"
    rows = []
    for i in range(4):
        row = state[i::4]
        rows.append(row[i:] + row[:i])
    newState = []
    for c in range(4):
        for r in range(4):
            newState.append(rows[r][c])
    return newState

def invShiftRows(state: list) -> list:
    assert len(state)==16, "State length must be 16 bytes"
    rows = []
    for i in range(4):
        row = state[i::4]
        rows.append(row[-i:] + row[:-i])
    newState = []
    for c in range(4):
        for r in range(4):
            newState.append(rows[r][c])
    return newState

def mixColumns(state: list) -> list:
    newState = []
    for i in range(16):
        r = const.MIX_COLUMNS_MTX[(i%4)*4:(i%4)*4+4]
        c = state[i-i%4:i-i%4+4]
        result = 0
        for j in range(4):
            result ^= c[j] if r[j]==1 else const.GALOIS_MULTIP[r[j]][c[j]]
        newState.append(result)
    return newState

def invMixColumns(state: list) -> list:
    newState = []
    for i in range(16):
        r = const.INV_MIX_COLUMNS_MTX[(i%4)*4:(i%4)*4+4]
        c = state[i-i%4:i-i%4+4]
        result = 0
        for j in range(4):
            result ^= c[j] if r[j]==1 else const.GALOIS_MULTIP[r[j]][c[j]]
        newState.append(result)
    return newState

def generateRoundKeys(hexaKey: str) -> list:
    assert len(hexaKey)==32, "Cipher key must be 128 byte length"
    aesKey = hexToDec(hexaKey)

    keys = []
    keys.append(aesKey)
    for i in range(10):
        prevKey = keys[i]
        curKey = []

        rcon = [const.RCON[i], 0, 0, 0]
        row0 = prevKey[12:]
        row0 = row0[1:] + row0[:1]
        row0 = subBytes(row0)
        curKey.extend(xorMatrix(xorMatrix(prevKey[0:4], row0), rcon))

        for j in range(3):
            curRow = curKey[j*4:j*4+4]
            prevRow = prevKey[j*4+4:j*4+8]
            curKey.extend(xorMatrix(prevRow, curRow))
        keys.append(curKey)
    return keys

def encryptBlock(hexaBlock:str, hexaKey:str) -> str:
    keys = generateRoundKeys(hexaKey)
    block = hexToDec(hexaBlock)
    block = xorMatrix(block, keys[0])

    for r in range(10):
        block = subBytes(block)
        block = shiftRows(block)

        if (r != 9):
            block = mixColumns(block)
        block = xorMatrix(block, keys[r+1])
    return decToHex(block)

def decryptBlock(hexaBlock:str, hexaKey:str) -> str:
    keys = generateRoundKeys(hexaKey)
    keys.reverse()
    block = hexToDec(hexaBlock)
    block = xorMatrix(block, keys[0])

    for r in range(10):
        block = invSubBytes(block)
        block = invShiftRows(block)

        if (r != 9):
            block = invMixColumns(block)
            block = xorMatrix(block, invMixColumns(keys[r + 1]))
        else:
            block = xorMatrix(block, keys[r+1])
    return decToHex(block)
