import os
import math
import time
import secrets
import hashlib
from contextlib import contextmanager


ENT = 256
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
    import sys
    import tty
    import termios
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        yield lambda: sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def progress(entropy_bits, need):
    need = max(entropy_bits, need)
    p = entropy_bits / need
    width = 50
    num_filled = int(width * entropy_bits // need)
    bar = '█' * num_filled + ' ' * (width - num_filled)
    print(f'\r{p:6.1%}|{bar}| {entropy_bits:.0f}/{need:.0f} bits', end='    \r')
    if p < 1:
        return True
    print()
    return False


def mnemonic(entropy, wordlist):
    assert len(entropy) % 4 == 0
    assert len(wordlist) == 2**11
    seed_num_bits = (len(entropy) * 8) // 32 * 33
    seed = entropy + hashlib.sha256(entropy).digest()
    seed_bits = ''.join(map('{:08b}'.format, seed))
    assert seed_num_bits <= len(seed_bits)
    words = []
    for i in range(0, seed_num_bits, 11):
        idx = int(seed_bits[i:i+11], 2)
        words.append(wordlist[idx])
    return ' '.join(words)


def entropy(num_bytes):
    user_bits = 0
    hasher = hashlib.shake_256(secrets.token_bytes(32))
    prev_c = b'\0'
    bins = {}
    with getgetch() as getch:
        while progress(user_bits, need=256):
            c = getch().encode()
            p_denom = bins[prev_c] = bins.get(prev_c, 0) + 1
            p_num = bins[prev_c + c] = bins.get(prev_c + c, 0) + 1
            user_bits += math.log2(p_denom / p_num)
            hasher.update(time.time_ns().to_bytes(16, 'big'))
            hasher.update(c)
            prev_c = c
    return hasher.digest(num_bytes)


def app():
    wodlist_path = os.path.join(os.path.dirname(__file__), 'wordlist/english.txt')
    wordlist = [line.strip() for line in open(wodlist_path)]
    assert mnemonic(bytes.fromhex('3f9284bcb5c089863d0c7068a83893944e3b0d48dacf5e60d65b9e27942dfe2b'), wordlist) == 'display neither connect high ancient seek vintage mix hamster dove ceiling chuckle together mammal casino fly fury allow notice detail junk black weather jaguar'  # noqa: E501
    assert mnemonic(bytes.fromhex('335ab07f496eba24ce9671e2c117a5ce0140ee2263aad6f1052c94ac95a37544'), wordlist) == 'crew stereo cabin name two bar demise soda tissue anger truly orchard beef jacket maze inspire street market enroll citizen sing spider steak manage'  # noqa: E501
    assert mnemonic(bytes.fromhex('5737726319c3e98229dc27d261e8241593a8cbad0b2aaa5ebf23eae16c0e2abe'), wordlist) == 'fire romance occur crime direct scissors polar lumber sponsor aunt animal clinic dentist grape reflect grab prevent vote similar still bitter alpha priority scissors'  # noqa: E501
    print(mnemonic(entropy(ENT//8), wordlist))
