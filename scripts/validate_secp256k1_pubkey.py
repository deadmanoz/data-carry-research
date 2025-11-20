#!/usr/bin/env python3
"""
Validate public keys on Bitcoin's secp256k1 curve.

This script checks whether a given public key represents a valid point on the
secp256k1 elliptic curve used by Bitcoin. A valid point must satisfy the curve
equation: y² = x³ + 7 (mod p)

Usage:
    python validate_secp256k1_pubkey.py <pubkey_hex>

Examples:
    # Valid compressed public key
    python validate_secp256k1_pubkey.py \\
        02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc

    # Invalid/fake public key (data-carrying)
    python validate_secp256k1_pubkey.py \\
        02660224cd2ffbf92fada23aa883f0c51f2d55ae13394a40d6538ff2a63d0dce00
"""

# secp256k1 curve prime
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def is_valid_pubkey(pubkey_hex):
    """
    Check if a public key is a valid point on the secp256k1 curve.

    Args:
        pubkey_hex: Hex string of the public key (with or without 0x prefix)

    Returns:
        bool: True if the public key is a valid curve point, False otherwise
    """
    # Remove 0x prefix if present
    if pubkey_hex.startswith('0x') or pubkey_hex.startswith('0X'):
        pubkey_hex = pubkey_hex[2:]

    try:
        pub_bytes = bytes.fromhex(pubkey_hex)
    except ValueError:
        return False

    if len(pub_bytes) == 33:  # Compressed public key
        prefix, x = pub_bytes[0], int.from_bytes(pub_bytes[1:], 'big')

        # Check prefix is valid (must be 0x02 or 0x03)
        if prefix not in (0x02, 0x03):
            return False

        # Calculate y² = x³ + 7 (mod p)
        y_squared = (pow(x, 3, p) + 7) % p

        # Calculate y using Tonelli-Shanks algorithm
        # For secp256k1: y = y_squared^((p+1)/4) mod p
        y = pow(y_squared, (p + 1) // 4, p)

        # Verify y² = y_squared (mod p)
        if pow(y, 2, p) != y_squared:
            return False

        # For any valid x, there are two valid y values: y and p - y (they have opposite parity)
        # If the calculated y doesn't match the prefix parity, use the other root
        # 0x02 = even y, 0x03 = odd y
        if (y % 2 == 1) == (prefix == 0x02):
            y = p - y

        # Verify the final y matches the expected parity
        return (y % 2 == 0) == (prefix == 0x02)

    elif len(pub_bytes) == 65:  # Uncompressed public key
        # First byte must be 0x04
        if pub_bytes[0] != 0x04:
            return False

        x = int.from_bytes(pub_bytes[1:33], 'big')
        y = int.from_bytes(pub_bytes[33:], 'big')

        # Verify the curve equation: y² = x³ + 7 (mod p)
        return (pow(y, 2, p) - pow(x, 3, p) - 7) % p == 0

    return False


def main():
    """Command-line interface for the validator."""
    import sys

    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    pubkey_hex = sys.argv[1]

    is_valid = is_valid_pubkey(pubkey_hex)

    print(f"Public key: {pubkey_hex}")
    print(f"Valid point on secp256k1: {is_valid}")

    if is_valid:
        print("✓ This is a valid public key")
    else:
        print("✗ This is NOT a valid public key (likely data-carrying)")

    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
