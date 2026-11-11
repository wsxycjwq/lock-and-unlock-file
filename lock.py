import os
import struct
import sys
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"LOCK2"
SALT_SIZE = 16
BASE_NONCE_SIZE = 8
NONCE_COUNTER_SIZE = 4
CHUNK_SIZE = 4 * 1024 * 1024
PBKDF2_ITERATIONS = 300_000


def show_progress(processed: int, total: int) -> None:
    percent = 100 if total == 0 else min(100, processed * 100 // total)
    bar_length = 30
    filled = bar_length * percent // 100
    bar = "#" * filled + "-" * (bar_length - filled)
    sys.stdout.write(f"\rEncrypting: [{bar}] {percent:3d}%")
    sys.stdout.flush()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    total_size = input_path.stat().st_size
    processed = 0
    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(BASE_NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    header = MAGIC + salt + base_nonce

    with input_path.open("rb") as source, output_path.open("wb") as target:
        target.write(header)
        show_progress(0, total_size)
        chunk_number = 0

        while True:
            data = source.read(CHUNK_SIZE)
            if not data:
                break

            if chunk_number >= 2**32:
                raise ValueError("输入文件包含过多数据块。")

            nonce = base_nonce + struct.pack(">I", chunk_number)
            encrypted = aesgcm.encrypt(nonce, data, header)
            target.write(struct.pack(">I", len(encrypted)))
            target.write(encrypted)
            chunk_number += 1
            processed += len(data)
            show_progress(processed, total_size)

    print()


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: python {Path(sys.argv[0]).name} <input-file> <output-file>")
        return 2

    input_path = Path(sys.argv[1]).resolve()
    output_path = Path(sys.argv[2]).resolve()

    if not input_path.is_file():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1
    if input_path == output_path:
        print("Error: input and output files must be different.", file=sys.stderr)
        return 2
    if output_path.exists():
        print(f"Error: output file already exists: {output_path}", file=sys.stderr)
        return 1

    password = getpass("Encryption password: ")
    if not password:
        print("Error: password cannot be empty.", file=sys.stderr)
        return 2
    if password != getpass("Confirm encryption password: "):
        print("Error: passwords do not match.", file=sys.stderr)
        return 2

    try:
        encrypt_file(input_path, output_path, password)
    except (OSError, ValueError) as error:
        print(f"Error: encryption failed: {error}", file=sys.stderr)
        return 1

    print(f"Encryption complete: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
