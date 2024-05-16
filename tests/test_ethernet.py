import itertools
import re

import pytest

from wireshark_digest_to_sqlite import ethernet

HEX_ETH_ADDR_FIRST_BYTE = re.compile(
    "^([0-9a-f]{2})(?::[0-9a-f]{2}){5}$", re.IGNORECASE
)


@pytest.mark.parametrize(
    "local, group, test_repeats",
    itertools.product([True, False], [True, False], range(5)),
)
def test_random_eth_addr(local, group, test_repeats):
    """Test the random_eth_addr routine."""
    addr = ethernet.random_eth_addr(local, group)

    addr_match = HEX_ETH_ADDR_FIRST_BYTE.match(addr)
    assert addr_match

    [byte0] = addr_match.groups()
    byte0 = int(byte0, base=16)
    assert byte0 & ethernet.LOCAL_MASK == local * ethernet.LOCAL_MASK
    assert byte0 & ethernet.GROUP_MASK == group * ethernet.GROUP_MASK


@pytest.mark.parametrize(
    "addr, oui",
    [
        ("00:00:00:00:00:00", 0),
        ("ac:de:48:01:02:03", 11329096),
        ("ff:ff:ff:00:00:00", 16777215),
    ],
)
def test_oui_from_hex_addr(addr, oui):
    """Test the oui_from_hex_addr routine."""
    assert ethernet.oui_from_hex_addr(addr) == oui
