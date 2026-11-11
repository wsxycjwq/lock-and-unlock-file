import os
import struct
import sys
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"LOCK2"
SALT_SIZE = 16
BASE_NONCE_SIZE = 8
NONCE_COUNTER_SIZE = 4
AUTH_TAG_SIZE = 16
CHUNK_SIZE = 4 * 1024 * 1024
PBKDF2_ITERATIONS = 300_000
HEADER_SIZE = len(MAGIC) + SALT_SIZE + BASE_NONCE_SIZE


def show_progress(processed: int, total: int) -> None:
    percent = 100 if total == 0 else min(100, processed * 100 // total)
    bar_length = 30
    filled = bar_length * percent // 100
    bar = "#" * filled + "-" * (bar_length - filled)
    sys.stdout.write(f"\rDecrypting: [{bar}] {percent:3d}%")
    sys.stdout.flush()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    total_size = input_path.stat().st_size
    processed = 0
    with input_path.open("rb") as source:
        header = source.read(HEADER_SIZE)
        processed = len(header)
        if len(header) != HEADER_SIZE or not header.startswith(MAGIC):
            raise ValueError("不是有效的 LOCK2 加密文件。")

        salt = header[len(MAGIC):len(MAGIC) + SALT_SIZE]
        base_nonce = header[-BASE_NONCE_SIZE:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        with output_path.open("wb") as target:
            chunk_number = 0
            show_progress(processed, total_size)
            while True:
                length_data = source.read(4)
                if not length_data:
                    break
                if len(length_data) != 4:
                    raise ValueError("加密文件已损坏：缺少数据块长度。")

                encrypted_length = struct.unpack(">I", length_data)[0]
                if encrypted_length < AUTH_TAG_SIZE or encrypted_length > CHUNK_SIZE + AUTH_TAG_SIZE:
                    raise ValueError("加密文件已损坏：数据块长度无效。")

                encrypted = source.read(encrypted_length)
                if len(encrypted) != encrypted_length:
                    raise ValueError("加密文件已损坏：数据块不完整。")

                if chunk_number >= 2**32:
                    raise ValueError("加密文件包含过多数据块。")
                nonce = base_nonce + struct.pack(">I", chunk_number)
                target.write(aesgcm.decrypt(nonce, encrypted, header))
                chunk_number += 1
                processed += 4 + encrypted_length
                show_progress(processed, total_size)

    print()


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: python {Path(sys.argv[0]).name} <input-file> <output-file>")
        return 2

    input_path = Path(sys.argv[1]).resolve()
    output_path = Path(sys.argv[2]).resolve()
    temporary_path = output_path.with_name(output_path.name + ".tmp")

    if not input_path.is_file():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1
    if input_path == output_path:
        print("Error: input and output files must be different.", file=sys.stderr)
        return 2
    if output_path.exists():
        print(f"Error: output file already exists: {output_path}", file=sys.stderr)
        return 1

    password = getpass("Decryption password: ")
    if not password:
        print("Error: password cannot be empty.", file=sys.stderr)
        return 2

    try:
        decrypt_file(input_path, temporary_path, password)
        os.replace(temporary_path, output_path)
    except InvalidTag:
        print("Error: incorrect password or corrupted data.", file=sys.stderr)
        if temporary_path.exists():
            temporary_path.unlink()
        return 1
    except (OSError, ValueError) as error:
        print(f"Error: decryption failed: {error}", file=sys.stderr)
        if temporary_path.exists():
            temporary_path.unlink()
        return 1

    print(f"Decryption complete: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
