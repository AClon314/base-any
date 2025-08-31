import pytest
from base_any import *


@pytest.mark.parametrize(
    "In",
    [
        ("我自横刀向天笑"),
    ],
)
def test_basic(
    In: str,
):
    text = encode_base(In.encode())
    Bin = base_decode(text)
    text2 = encode_base(Bin)
    Log.debug(f"{text=}")
    assert text == text2
    assert In == Bin.decode()
