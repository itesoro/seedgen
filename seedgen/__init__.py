import os
import math
import secrets
import hashlib
from contextlib import contextmanager


ENT = 160
assert ENT % 32 == 0 and 160 <= ENT <= 256


@contextmanager
def getgetch():
    try:
        import msvcrt
    except ImportError:
        pass
    else:
        yield msvcrt.getch
        return
    import sys, tty, termios
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        yield lambda: sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def progress(entropy_bits, need):
    p = min(entropy_bits / need, 1)
    width = 50
    num_filled = int(width * entropy_bits // need)
    bar = '█' * num_filled + ' ' * (width - num_filled)
    print(f'\r{p:6.1%}|{bar}| {entropy_bits:.0f}/{need} bits', end = '    \r')
    if p < 1:
        return True
    print()
    return False


# Copied from https://github.com/trezor/python-mnemonic/blob/master/mnemonic/mnemonic.py
def to_mnemonic(data, wordlist):
    assert len(wordlist) == 2048
    h = hashlib.sha256(data).hexdigest()
    b = (
        bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)
        + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
    )
    words = []
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        words.append(wordlist[idx])
    return ' '.join(words)


def app():
    raw_entropy = bytearray(secrets.token_bytes(32))
    entropy_bits = 0
    bins = {}
    with getgetch() as getch:
        while progress(entropy_bits, need=256):
            prev_c = bytes(raw_entropy[-1:])
            c = getch().encode()
            p_denom = bins[prev_c] = bins.get(prev_c, 0) + 1
            p_num = bins[prev_c + c] = bins.get(prev_c + c, 0) + 1
            entropy_bits += math.log2(p_denom / p_num)
            raw_entropy += c
    data = hashlib.sha512(raw_entropy).digest()[:ENT//8]
    wodlist_path = os.path.join(os.path.dirname(__file__), 'wordlist/english.txt')
    wordlist = [line.strip() for line in open(wodlist_path)]
    print(to_mnemonic(data, wordlist))
