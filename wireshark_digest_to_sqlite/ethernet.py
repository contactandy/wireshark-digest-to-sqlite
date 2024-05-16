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
LOCAL_MASK = 0x01
GROUP_MASK = 0x02
ETH_ADDR_BYTE_LEN = 6


def random_eth_addr(local=False, group=False):
    """
    Generate a random ethernet address in colon-separated hex notation.
    Arguments set if the address is local or not and group or unicast.
    """
    first_byte = set_mask_bits(secrets.randbits(BITS_PER_BYTE), LOCAL_MASK, local)
    first_byte = set_mask_bits(first_byte, GROUP_MASK, group)

    first_byte = bytes([first_byte])
    addr = first_byte + secrets.token_bytes(ETH_ADDR_BYTE_LEN - 1)
    return addr.hex(":")


OUI_BYTES = 3


def is_local(addr):
    """
    Returns if an ethernet address is a local address instead of a universal
    one.
    """
    first_byte, _others = addr.split(":", maxsplit=1)
    first_byte = int(first_byte, base=16)
    return bool(first_byte & LOCAL_MASK)


def is_group(addr):
    """
    Returns if an ethernet address is a group address instead of an individual
    one.
    """
    first_byte, _others = addr.split(":", maxsplit=1)
    first_byte = int(first_byte, base=16)
    return bool(first_byte & GROUP_MASK)


def oui_from_hex_addr(addr):
    """
    Return the organizationally unique identifier of a universal ethernet
    address.
    """
    oui_hex = "".join(addr.split(":")[:OUI_BYTES])
    return int(oui_hex, base=16)
