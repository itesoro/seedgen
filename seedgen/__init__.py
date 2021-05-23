import os
import math
import time
import secrets
import hashlib
from collections import defaultdict
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
    entropy_bits = int(entropy_bits)
    need = max(entropy_bits, need)
    p = entropy_bits / need
    width = 50
    num_filled = int(width * entropy_bits // need)
    bar = '█' * num_filled + ' ' * (width - num_filled)
    print(f'\r{p:6.1%}|{bar}| {entropy_bits}/{need} bits', end='    \r')
    if p < 1:
        return True
    print()
    return False


def entropy(text):
    num_bits = 0
    counts = defaultdict(lambda: 0)
    for i in range(len(text) - 1):
        counts[text[i]] += 1
        counts[text[i:i+2]] += 1
    for i in range(len(text) - 1):
        num_bits += math.log2(counts[text[i]] / counts[text[i:i+2]])
    return num_bits


def random_bytes(num):
    hasher = hashlib.sha3_512(secrets.token_bytes(num))
    assert num <= hasher.digest_size
    user_input = b'\0\0'
    triples = set()
    with getgetch() as getch:
        while progress(entropy(user_input), need=256):
            c = getch().encode()
            triple = user_input[-2:] + c
            if triple in triples:
                continue
            triples.add(triple)
            user_input += c
            hasher.update(time.time_ns().to_bytes(16, 'big'))
            hasher.update(c)
    return hasher.digest()[:num]


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


def app():
    wodlist_path = os.path.join(os.path.dirname(__file__), 'wordlist/english.txt')
    wordlist = [line.strip() for line in open(wodlist_path)]
    assert mnemonic(bytes.fromhex('3f9284bcb5c089863d0c7068a83893944e3b0d48dacf5e60d65b9e27942dfe2b'), wordlist) == 'display neither connect high ancient seek vintage mix hamster dove ceiling chuckle together mammal casino fly fury allow notice detail junk black weather jaguar'  # noqa: E501
    assert mnemonic(bytes.fromhex('335ab07f496eba24ce9671e2c117a5ce0140ee2263aad6f1052c94ac95a37544'), wordlist) == 'crew stereo cabin name two bar demise soda tissue anger truly orchard beef jacket maze inspire street market enroll citizen sing spider steak manage'  # noqa: E501
    assert mnemonic(bytes.fromhex('5737726319c3e98229dc27d261e8241593a8cbad0b2aaa5ebf23eae16c0e2abe'), wordlist) == 'fire romance occur crime direct scissors polar lumber sponsor aunt animal clinic dentist grape reflect grab prevent vote similar still bitter alpha priority scissors'  # noqa: E501
    print(mnemonic(random_bytes(ENT//8), wordlist))
