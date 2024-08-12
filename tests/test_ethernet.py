"""Test routines in the ethernet module."""

import itertools
import re
from contextlib import nullcontext as does_not_raise

import pytest

from wireshark_digest_to_sqlite import ethernet

HEX_ETH_ADDR_FIRST_BYTE = re.compile(
    "^([0-9a-f]{2})(?::[0-9a-f]{2}){5}$", re.IGNORECASE
)


def test_eth_addr():
    """Test the EthAddr class with overall tests."""
    sample_address = "ed:b7:2f:d1:78:80"
    sample_address_oui = 15578927
    sample_address_nic = 13727872
    addr = ethernet.EthAddr(sample_address)
    assert addr.human_friendly_form == sample_address
    assert str(addr) == sample_address
    assert addr.normalized == b"\xed\xb7\x2f\xd1\x78\x80"
    assert addr.is_local
    assert not addr.is_group
    assert addr.oui == sample_address_oui
    assert addr.nic == sample_address_nic


def test_eth_addr_formats():
    """Test possible formats to initialize the EthAddr class."""
    components = ("ed", "b7", "2f", "d1", "78", "80", "27", "ab")
    addr_len = ethernet.EthAddr.ETH_ADDR_BYTE_LEN

    for good_sep in [":", ".", ""]:
        with does_not_raise():
            well_formed_addr = good_sep.join(components[:addr_len])
            ethernet.EthAddr(well_formed_addr)

    for bad_sep in [",", "*"]:
        with pytest.raises(ethernet.UnrecognizedEthernetAddressFormat):
            poorly_formed_addr = bad_sep.join(components[:addr_len])
            ethernet.EthAddr(poorly_formed_addr)

    for i in range(len(components)):
        if i == addr_len:
            expectation = does_not_raise()
        else:
            expectation = pytest.raises(ethernet.UnrecognizedEthernetAddressFormat)

        with expectation:
            ethernet.EthAddr(":".join(components[:i]))

    bad_components = ["&x", "123", "ab3", "AB", "1A", "na", "an", "a", ""]
    for i, bad_component in itertools.product(range(addr_len), bad_components):
        mixed_components = components[:i] + tuple(bad_components) + components[i + 1 :]
        with pytest.raises(ethernet.UnrecognizedEthernetAddressFormat):
            ethernet.EthAddr(":".join(mixed_components))


def test_addr_scope():
    """Test EthAddr is_local and is_group properties."""
    addr_end = ":".join(("ed", "b7", "2f", "d1", "78", "80", "27", "ab")[1:6])
    for byte0 in range(256):
        addr = ethernet.EthAddr(f"{byte0:02x}:{addr_end}")
        assert bool(byte0 & ethernet.EthAddr.LOCAL_MASK) == addr.is_local
        assert bool(byte0 & ethernet.EthAddr.GROUP_MASK) == addr.is_group


@pytest.mark.parametrize(
    "local, group",
    itertools.product([True, False], [True, False]),
)
def test_random_eth_addr(local, group):
    """Test EthAddr's random_eth_addr routine."""
    for _test_ind in range(100):
        addr = ethernet.EthAddr.random_eth_addr(local, group)
        assert addr.is_local == local
        assert addr.is_group == group


@pytest.mark.parametrize(
    "addr, oui",
    [
        ("00:00:00:00:00:00", 0),
        ("ac:de:48:01:02:03", 11329096),
        ("ff:ff:ff:00:00:00", 16777215),
    ],
)
def test_eth_addr_oui(addr, oui):
    """Test the oui property of EthAddr."""
    assert ethernet.EthAddr(addr).oui == oui
