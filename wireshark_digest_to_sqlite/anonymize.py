"""Tool to anonymize the ethernet information in a json wireshark digest."""

import argparse
import json
import logging
import pathlib

from wireshark_digest_to_sqlite import ethernet


def addr_tree_digest(addr, direction):
    """
    Return the wireshark digest tree for an address. The oui values resolve
    to `Randomized`.
    """
    oui = f"{ethernet.oui_from_hex_addr(addr):d}"
    OUI_RESOLVED = "Randomized"
    local = f"{ethernet.is_local(addr):d}"  # `True` becomes "1"
    group = f"{ethernet.is_group(addr):d}"
    return {
        f"eth.{direction}_resolved": addr,
        f"eth.{direction}.oui": oui,
        f"eth.{direction}.oui_resolved": OUI_RESOLVED,
        "eth.addr": addr,
        "eth.addr_resolved": addr,
        "eth.addr.oui": oui,
        "eth.addr.oui_resolved": OUI_RESOLVED,
        f"eth.{direction}.lg": local,
        "eth.lg": local,
        f"eth.{direction}.ig": group,
        "eth.ig": group,
    }


def randomize_ethernet_addresses(digest):
    """
    Replaces (in place) ethernet addresses found in digest with randomized
    addresses. Returns the mapping between original addresses and replaced
    addresses.
    """
    replaced = {}
    for packet in digest:
        eth_layer = packet["_source"]["layers"].get("eth")
        if not eth_layer:
            continue
        for direction in ["src", "dst"]:
            og_addr = eth_layer.get(f"eth.{direction}")
            if not og_addr:
                continue
            anon_addr = replaced.setdefault(
                og_addr, ethernet.random_eth_addr(local=True, group=False)
            )
            eth_layer[f"eth.{direction}"] = anon_addr
            anon_addr_tree = addr_tree_digest(anon_addr, direction)
            eth_layer[f"eth.{direction}_tree"] = anon_addr_tree

    return replaced


def contains_substrings(digest, values):
    """
    Returns if any of values is a substring of the string representation of the
    input json.
    """
    digest_str = json.dumps(digest)
    return any(value in digest_str for value in values)


class ScrubbingException(Exception):
    """Raise if unable to fully anonymize a digest."""


def anonymize_digest(digest):
    """Replace ethernet addresses found in a digest with randomized addresses."""
    replaced = randomize_ethernet_addresses(digest)
    if contains_substrings(digest, replaced.keys()):
        raise ScrubbingException


PARSER = argparse.ArgumentParser(
    description="Anonymize the ethernet information in a json wireshark digest.",
)
PARSER.add_argument("input", help="path to digest to anonymize", type=pathlib.Path)
PARSER.add_argument("output", help="path to place anonymized digest", type=pathlib.Path)


def main(digest_path, output_path):
    """
    Anonymize wireshark digest at digest_path and overwrite.
    """
    digest = json.loads(digest_path.read_text())
    try:
        anonymize_digest(digest)
    except ScrubbingException:
        logging.error(
            "Failed to remove all instances of the original ethernet addresses!"
        )
    finally:
        output_path.write_text(json.dumps(digest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    args = PARSER.parse_args()
    main(args.input, args.output)
