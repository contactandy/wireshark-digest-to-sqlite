"""Provide capabilities to parse ethernet addresses and generate random ones
to specification."""

import re
import secrets


def set_mask_bits_on(val, mask):
    """
    Return val with any bits in mask to on.
    """
    return val | mask


def set_mask_bits_off(val, mask):
    """
    Return val with any bits in mask to off.
    """
    return val & (~mask)


def set_mask_bits(val, mask, on):
    """
    Return val with any bits in mask to given on or off.
    """
    if on:
        return set_mask_bits_on(val, mask)
    return set_mask_bits_off(val, mask)


BITS_PER_BYTE = 8


class UnrecognizedEthernetAddressFormat(Exception):
    """Raise when unable to parse human readable form of an ethernet address."""


class EthAddr:
    OUI_BYTES = 3
    LOCAL_MASK = 0x01
    GROUP_MASK = 0x02
    ETH_ADDR_BYTE_LEN = 6

    HEX_ETH_ADDR_FORMATS = tuple(
        re.compile(
            rf"""
                ^
                ([a-z0-9]{{2}})      
                {sep}([a-z0-9]{{2}}) 
                {sep}([a-z0-9]{{2}}) 
                {sep}([a-z0-9]{{2}}) 
                {sep}([a-z0-9]{{2}}) 
                {sep}([a-z0-9]{{2}}) 
                $
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        )
        # `:` format used by wireshark, for example
        # `.` format used by IEEE 802, for example
        for sep in [":", "\.", ""]
    )

    def __init__(self, human_friendly_form):
        match_attempts = [
            addr_format.match(human_friendly_form)
            for addr_format in self.HEX_ETH_ADDR_FORMATS
        ]

        try:
            [success_match] = [
                addr_match for addr_match in match_attempts if addr_match
            ]
        except ValueError:
            raise UnrecognizedEthernetAddressFormat(
                "Didn't find six hex components in human readable format: "
                f"`{human_friendly_form}`."
            )

        self.normalized = bytes.fromhex("".join(success_match.groups()))
        self.human_friendly_form = human_friendly_form

    @property
    def is_local(self):
        """
        Returns if an ethernet address is a local address instead of a universal
        one.
        """
        return bool(self.normalized[0] & self.LOCAL_MASK)

    @property
    def is_group(self):
        """
        Returns if an ethernet address is a group address instead of an individual
        one.
        """
        return bool(self.normalized[0] & self.GROUP_MASK)

    @property
    def oui(self):
        """
        Return the organizationally unique identifier of a universal ethernet
        address.
        """
        return int.from_bytes(self.normalized[: self.OUI_BYTES], byteorder="big")

    @property
    def nic(self):
        """
        Return the network interface controller specfic part of a universal
        ethernet address.
        """
        return int.from_bytes(self.normalized[self.OUI_BYTES :], byteorder="big")

    @classmethod
    def random_eth_addr(cls, local=False, group=False):
        """
        Generate a random ethernet address in colon-separated hex notation.
        Arguments set if the address is local or not and group or unicast.
        """
        first_byte = set_mask_bits(
            secrets.randbits(BITS_PER_BYTE), cls.LOCAL_MASK, local
        )
        first_byte = set_mask_bits(first_byte, cls.GROUP_MASK, group)

        first_byte = bytes([first_byte])
        addr = first_byte + secrets.token_bytes(cls.ETH_ADDR_BYTE_LEN - 1)
        return cls(addr.hex(":"))

    def __repr__(self):
        """Return the human readable form of an ethernet address."""
        return self.human_friendly_form
