#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path


def remove_output_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare_output_file_path(path: Path) -> None:
    parent = path.parent
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise SystemExit(f"Refusing to write generated wordlist through non-regular output parent: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        remove_output_path(path)


def generate_wordlist_source(wordlist_path: Path, output_path: Path) -> None:
    words = [
        line.strip()
        for line in wordlist_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    if len(words) != 2048:
        raise SystemExit(f"BIP-39 English wordlist must contain 2048 words, found {len(words)}.")
    if len(set(words)) != len(words):
        raise SystemExit("BIP-39 English wordlist contains duplicate words.")
    if words != sorted(words):
        raise SystemExit("BIP-39 English wordlist must be sorted.")
    for word in words:
        if not re.fullmatch(r"[a-z]+", word):
            raise SystemExit(f"BIP-39 English wordlist contains an unsupported word: {word!r}")

    lines = [
        '#include "bip39_wordlist.h"',
        "",
        "namespace signing {",
        "namespace {",
        "",
        "constexpr const char* kBip39EnglishWords[2048] = {",
    ]
    for word in words:
        lines.append(f'    "{word}",')
    lines.extend(
        [
            "};",
            "",
            "}  // namespace",
            "",
            "const char* bip39_english_word(uint16_t index)",
            "{",
            "    if (index >= 2048) {",
            "        return nullptr;",
            "    }",
            "    return kBip39EnglishWords[index];",
            "}",
            "",
            "}  // namespace signing",
            "",
        ]
    )
    output = "\n".join(lines)
    prepare_output_file_path(output_path)
    if output_path.exists() and output_path.read_text(encoding="utf-8") == output:
        return
    output_path.write_text(output, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: generate_bip39_wordlist.py /path/to/english.txt "
            "/path/to/bip39_wordlist.cpp",
            file=sys.stderr,
        )
        return 2

    generate_wordlist_source(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
