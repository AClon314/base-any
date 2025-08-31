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
from bitstring import Bits, BitArray

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(asctime)s %(name)s:%(lineno)d\t%(message)s",
    datefmt="%M:%S",
)
Log = logging.getLogger(__name__)

BASEU_TXT = Path("baseU.txt")
PAD = "="
MD5_DICT = "aea64798c59a0dc12f0196342eba0fd1"
T_BIT_ORDER = Literal["little", "big"]


def encode_base(
    In: Path | bytes, Dict: Path | str = BASEU_TXT, byteorder: T_BIT_ORDER = "big"
):
    dic = read_file(Dict)[0]
    bits_per_char = int(log(len(dic), 2))
    dic = dic[: 2**bits_per_char]
    Bin = read_file(In, mode="rb")[0]

    # 使用 bitstring 处理数据
    bit_data = Bits(bytes=Bin)
    len_Bin_bits = len(bit_data)

    Log.debug(
        f"split {len_Bin_bits=} bits into {ceil(len_Bin_bits / bits_per_char)} chars, every {bits_per_char=} bits as a char."
    )

    text = ""
    # 按字符所需的bit数分割bit串
    len_no_pad = len_Bin_bits // bits_per_char
    for i in range(len_no_pad):
        _i = i * bits_per_char
        bit_chunk = bit_data[_i : _i + bits_per_char]
        index = bit_chunk.uint
        text += dic[index]
    Log.debug(f"{index=}")

    # 处理剩余的bit
    if (remain_bits := len_Bin_bits % bits_per_char) != 0:
        # 获取剩余的bit
        remaining_bits = bit_data[-remain_bits:]
        index = remaining_bits.uint
        # 用等号填充缺失的bit数
        text += dic[index]
        # if len_no_pad != 0:
        pad = PAD * (bits_per_char - remain_bits)
        text += pad
        Log.debug(f"{index=}")

    return text


def base_decode(
    In: Path | str, Dict: Path | str = BASEU_TXT, byteorder: T_BIT_ORDER = "big"
):
    text, dic = read_file(In, Dict)
    len_text = len(text)
    text, eof_char, len_pad_bits = read_padding(text)

    bits_per_char = int(log(len(dic), 2))
    Log.debug(f"merge {len_text} chars into bits, then convert to bytes.")

    # 使用 bitstring 收集所有bit
    bits = BitArray()
    for i, C in enumerate(text):
        index = char_to_index(dic, C, i)
        # 转换为固定长度的bit字符串
        char_bits = Bits(uint=index, length=bits_per_char)
        bits.append(char_bits)
        Log.debug(f"{C=} {index=} {char_bits=}")

    if eof_char:
        index = char_to_index(dic, eof_char, -1)
        char_bits = Bits(uint=index, length=bits_per_char - len_pad_bits)
        bits.append(char_bits)
        Log.debug(f"{len_pad_bits=}")

    try:
        Bin: bytes = bits.bytes
    except ValueError as e:
        if len(e.args) > 0 and "bits" in e.args[0]:
            len_bits = len(bits)
            len_pad = len_bits % 8
            e.add_note(
                f"Forget '{PAD*len_pad}' at end of file? ({len_pad} of {PAD=}), or try with arg '--bit {bits_per_char-len_pad}'"
            )
            raise e

    Log.debug(f"{len(Bin)=}")
    return Bin


def char_to_index(dic: str, char: str, pos: int):
    try:
        index = dic.index(char)
    except ValueError as e:
        e.add_note(
            f"Character {char!r} at {pos} not found in dict, try args '--bit {int(log(len(dic), 2)//8)+8}'"
        )
        raise e
    return index


def read_padding(text: str):
    # 计算末尾等号的数量，表示缺失的bit数
    pad_len_bits = text.count(PAD)
    text = text.rstrip(PAD)
    pad_char = ""
    if pad_len_bits > 0:
        pad_char = text[-1]
        text = text[:-1]
    Log.debug(f"{pad_char=} {pad_len_bits=}")
    return text, pad_char, pad_len_bits


def genDict(blacklist=" " + PAD, dic: Path = BASEU_TXT, skip_check=False):
    if dic.exists():
        with open(dic, "r") as f:
            Dict = f.read()
        md5_Dict = md5(Dict.encode()).hexdigest()
        Log.debug(f"{md5_Dict=}\t{MD5_DICT=}")
        try:
            assert md5_Dict == MD5_DICT
        except AssertionError:
            Log.warning(f"Using {dic=}")
            if not skip_check:
                raise
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
    len_bits = int(2**ns.bit)
    Dict = genDict(dic=ns.dic, skip_check=ns.dic)
    assert (
        len(Dict) >= len_bits
    ), f"args '--bit {ns.bit}'={len_bits} > {len(Dict)=}, {len_bits-len(Dict)=}, use smaller value for '--bit', or expand {ns.dic}"
    Log.debug(f"{len(Dict)=} {len_bits=}")
    Dict = Dict[:len_bits]
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
                # 支持bit输入
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
        help="[Encode] hex encoded (0123456789abcdef)",
    )
    parser.add_argument(
        "-b", "--bin", action="store_true", help="[Encode] binary encoded (01)"
    )
    parser.add_argument("-d", "--decode", action="store_true", help="[Decode] mode")
    parser.add_argument(
        "-B",
        "--bit",
        type=int,
        default=16,
        help="len(bit) per 1 encoded char, can be 1~17 (cause printable unicode upto 2^17)",
    )
    parser.add_argument(
        "-D", "--dic", default=BASEU_TXT, help=f"Default at: {BASEU_TXT}"
    )
    parser.add_argument("--verbose", action="store_true", help="print debug logging")
    ns, args = parser.parse_known_args()
    if ns.verbose:
        Log.setLevel(logging.DEBUG)
    ns.dic = Path(ns.dic)
    return ns, args


if __name__ == "__main__":
    main()
