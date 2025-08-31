#!/bin/env python
"""
By default, Dict have all Log.debugable chars except space and '='
"""
import sys
from hashlib import md5
from math import ceil, log
from pathlib import Path
from typing import Any, Literal, overload
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(asctime)s %(name)s:%(lineno)d\t%(message)s",
    datefmt="%M:%S",
)
Log = logging.getLogger(__name__)

BASEU_TXT = Path("baseU.txt")
EOF = "="
MD5_DICT = "aea64798c59a0dc12f0196342eba0fd1"
T_BIT_ORDER = Literal["little", "big"]


def encode_base(
    In: Path | bytes, Dict: Path | str = BASEU_TXT, byteorder: T_BIT_ORDER = "big"
):
    dic = read_file(Dict)[0]
    bytes_per_char = int(log(len(dic), 2) / 8)
    dic = dic[: 2 ** (bytes_per_char * 8)]
    Bin = read_file(In, mode="rb")[0]
    len_Bin = len(Bin)
    Log.debug(
        f"split {len_Bin=} into {ceil(len_Bin / bytes_per_char)} chars, every {bytes_per_char=} as a char."
    )
    text = ""
    for i in range(len_Bin // bytes_per_char):
        _i = i * bytes_per_char
        Bytes = Bin[_i : _i + bytes_per_char]
        index = int.from_bytes(Bytes, byteorder)
        Log.debug(f"{index=}")
        text += dic[index]
    if (remain := len_Bin % bytes_per_char) != 0:
        Bytes = Bin[len_Bin - remain :]
        index = int.from_bytes(Bytes, byteorder)
        text += dic[index] + EOF * (bytes_per_char - remain)
        Log.debug(f"{index=}")
    return text


def base_decode(
    In: Path | str, Dict: Path | str = BASEU_TXT, byteorder: T_BIT_ORDER = "big"
):
    text, dic = read_file(In, Dict)
    len_text = len(text)
    text, pad_char, pad_len_bytes = read_padding(text)

    bytes_per_char = int(log(len(dic), 2) / 8)
    Log.debug(
        f"merge {len_text} chars into {ceil(len(text) * bytes_per_char / 8)+pad_len_bytes} bytes."
    )
    Bin = b""
    for i, C in enumerate(text):
        index = char_to_index(dic, C, i)
        Bytes = index.to_bytes(bytes_per_char, byteorder)
        Bin += Bytes
    Log.debug(f"{C=} {index=}")

    if pad_char:
        index = char_to_index(dic, pad_char, -1)
        Log.debug(f"{bytes_per_char - pad_len_bytes=}")
        Bytes = index.to_bytes(bytes_per_char - pad_len_bytes, byteorder)
        Bin += Bytes

    Log.debug(f"{len(Bin)=}")
    return Bin


def char_to_index(dic: str, char: str, pos: int):
    try:
        index = dic.index(char)
    except ValueError as e:
        e.add_note(f"Character {char!r} at {pos} not found in dictionary")
        raise e
    return index


def read_padding(text: str):
    pad_len_bytes = text.count(EOF)
    text = text.rstrip(EOF)
    pad_char = text[-1]
    text = text[:-1]
    Log.debug(f"{pad_char=} {pad_len_bytes=}")
    return text, pad_char, pad_len_bytes


def genDict(blacklist=" " + EOF, dic: Path = BASEU_TXT, skip_check=False):
    if dic.exists():
        with open(dic, "r") as f:
            Dict = f.read()
        md5_Dict = md5(Dict.encode()).hexdigest()
        Log.debug(f"{md5_Dict=}\t{MD5_DICT=}")
        try:
            assert md5_Dict == MD5_DICT
        except AssertionError:
            Log.warning(f"Using custom Dict at {dic}")
            if not skip_check:
                raise
        Log.debug(f"chars Dict valid={len(Dict)}")
        return Dict
    Dict = ""
    i = -1
    valid = 0
    while True:
        i += 1
        try:
            C = chr(i)
        except ValueError:
            Log.debug(f"unicode max={i} ({i:#x})")
            break
        if not C.isprintable() or C in blacklist:
            continue
        Dict += C
        valid += 1
    with open(dic, "w") as f:
        f.write(Dict)
    Log.debug(f"chars Dict {valid=}\t({(valid*100/i):.0f}%)")
    return Dict


@overload
def read_file(*path: Path | Any, mode: Literal["r"] = "r") -> list[str]: ...
@overload
def read_file(*path: Path | Any, mode: Literal["rb"] = "rb") -> list[bytes]: ...


def read_file(*path: Path | Any, mode: Literal["r", "rb"] = "r"):
    DATA = list(path)
    for i, p in enumerate(path):
        if isinstance(p, Path):
            with open(p, mode) as f:
                DATA[i] = f.read()
                if isinstance(DATA[i], str):
                    DATA[i] = str(DATA[i]).strip()
    return DATA


def main():
    ns, args = parser()
    len_bits = int(2**ns.Bits)
    assert len_bits % 8 == 0, "currently only 8/16 bit codec is supported"
    Log.debug(f"{len_bits=}")
    Dict = genDict(skip_check=ns.custom)[:len_bits]
    path = Path(ns.input)

    In = path if path.exists() else str(ns.input)

    if ns.decode:
        result = base_decode(In, Dict)
        if sys.stdout.isatty():
            print(result)
        else:
            sys.stdout.buffer.write(result)
            sys.stderr.write("pipe mode, write to file")
    else:
        if isinstance(In, str):
            if ns.hex:
                In = bytes.fromhex(In)
            elif ns.bin:
                # TODO: support bits, currently bytes like 8,16 bits
                In = int(In, 2).to_bytes((len(In) + 7) // 8, byteorder="big")
            else:
                In = In.encode()
        result = encode_base(In, Dict)
        print(result)


def parser():
    import argparse

    parser = argparse.ArgumentParser(description="Base Any")
    parser.add_argument("input", type=str, help="Input Path or str")
    parser.add_argument(
        "-x",
        "--hex",
        action="store_true",
        help="[Encode] Input str is hex encoded (0123456789abcdef)",
    )
    # parser.add_argument(
    #     "-b", "--bit", action="store_true", help="[Encode] Input is bit encoded (01)"
    # )
    parser.add_argument("-d", "--decode", action="store_true", help="Decode mode")
    parser.add_argument(
        "-B", "--Bits", type=int, default=16, help="Bit len for codec Dict"
    )
    parser.add_argument(
        "--custom", action="store_true", help=f"Use custom base Dict at: {BASEU_TXT}"
    )
    parser.add_argument("--verbose", action="store_true", help="print debug logging")
    ns, args = parser.parse_known_args()
    if ns.verbose:
        Log.setLevel(logging.DEBUG)
    return ns, args


if __name__ == "__main__":
    main()
