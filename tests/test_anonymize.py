import copy
import json
import re
from collections.abc import Iterable
from unittest import mock

import pytest

from wireshark_digest_to_sqlite import anonymize, ethernet

HEX_ETH_ADDR = re.compile("^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)


def test_addr_tree_digest():
    """Test the addr_tree_digest routine."""
    direction = "src"
    addr = "ac:de:48:01:02:03"
    tree_digest = anonymize.addr_tree_digest(addr, direction)

    assert all(isinstance(value, str) for value in tree_digest.values())

    assert f"eth.{direction}_resolved" in tree_digest
    assert tree_digest["eth.addr"] == addr

    oui = str(ethernet.oui_from_hex_addr(addr))
    assert tree_digest["eth.addr.oui"] == oui

    assert tree_digest["eth.addr.oui_resolved"] == "Randomized"


def all_string_values(digest):
    """Return an iterable of all string objects in a json."""
    if isinstance(digest, str):
        yield digest
    elif isinstance(digest, list):
        for value in digest:
            yield from all_string_values(value)
    elif isinstance(digest, dict):
        for value in digest.values():
            yield from all_string_values(value)
    else:
        pass


def test_all_string_values(sample_digest):
    """Test all_string_values routine."""
    sample = ["0", "1", "2"]
    assert list(all_string_values(sample)) == sample

    assert list(all_string_values("0123")) == ["0123"]

    sample = {"a": ["0", "1"], "b": ["2"], "c": "3"}
    assert list(all_string_values(sample)) == ["0", "1", "2", "3"]

    sample = ["0", {"a": "1", "b": "2"}]
    assert list(all_string_values(sample)) == ["0", "1", "2"]

    sample_digest_strings = all_string_values(sample_digest)
    assert isinstance(sample_digest_strings, Iterable)
    sample_digest_strings = list(sample_digest_strings)
    assert all(isinstance(value, str) for value in sample_digest_strings)
    assert sample_digest[0]["_index"] in sample_digest_strings
    sample_value = sample_digest[0]["_source"]["layers"]["frame"]["frame.time"]
    assert sample_value in sample_digest_strings
    sample_value = sample_digest[-1]["_source"]["layers"]["frame"]["frame.time"]
    assert sample_value in sample_digest_strings


def test_randomize_ethernet_addresses(sample_digest):
    """Test the randomize_ethernet_addresses routine."""
    eth_addr_matches = [
        HEX_ETH_ADDR.match(value) for value in all_string_values(sample_digest)
    ]
    original_eth_addrs = [
        addr_match.group() for addr_match in eth_addr_matches if addr_match
    ]
    original_eth_addrs = list(set(original_eth_addrs))
    replaced = anonymize.randomize_ethernet_addresses(sample_digest)
    assert sorted(original_eth_addrs) == sorted(list(replaced.keys()))

    all_strings_in_replaced = list(all_string_values(sample_digest))
    assert not any(addr in all_strings_in_replaced for addr in original_eth_addrs)
    assert all(addr in all_strings_in_replaced for addr in replaced.values())

    assert not anonymize.contains_substrings(sample_digest, replaced.keys())
    replaced_digest_str = json.dumps(sample_digest)
    assert all(addr in replaced_digest_str for addr in replaced.values())


def test_contains_substrings(sample_digest):
    """Test the contains_substrings routine."""
    present = sample_digest[0]["_source"]["layers"]["frame"]["frame.time"]
    not_present = "icecreamsundayexternalrfid"
    bad_test_message = "Bad test! Didn't expect this value in the sample."
    assert not_present not in sample_digest, bad_test_message

    assert not anonymize.contains_substrings(sample_digest, [])
    assert not anonymize.contains_substrings(sample_digest, [not_present])
    assert anonymize.contains_substrings(sample_digest, [not_present, present])
    assert anonymize.contains_substrings(sample_digest, [present, present])


def test_anonymize(sample_digest):
    """Test the anonymize_digest routine."""
    original_digest = copy.deepcopy(sample_digest)
    anonymize.anonymize_digest(sample_digest)
    assert original_digest != sample_digest

    contains_substrings_function = (
        "wireshark_digest_to_sqlite.anonymize.contains_substrings"
    )
    with mock.patch(contains_substrings_function) as mock_contains:
        mock_contains.return_value = True
        with pytest.raises(anonymize.ScrubbingException):
            anonymize.anonymize_digest(sample_digest)
