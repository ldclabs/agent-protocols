#!/usr/bin/env python3
"""Exercise real Agent Mail encryption across all three SDKs.

Run from any directory after installing the workspace's Rust, TypeScript and
Python dependencies:
    .venv/bin/python tests/mail_interop.py

Each language adapter uses the public, deterministic identities and recipient
key in the normative vectors, but calls its SDK's production encryption API
with fresh randomness. Every resulting packet is opened by every language.
This test does not import the development vector checker or implement crypto.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ADAPTERS = {
    "Rust": ["cargo", "run", "--quiet", "-p", "agent-protocols", "--example", "mail_interop"],
    "Python": [sys.executable, "python/agent-protocols/tests/mail_interop.py"],
    "TypeScript": ["pnpm", "--filter", "agent-protocols", "exec", "tsx", "tests/mail_interop.ts"],
}


def invoke(language: str, request: dict, *, rejection: bool = False):
    result = subprocess.run(
        ADAPTERS[language], cwd=ROOT, input=json.dumps(request), text=True,
        capture_output=True, timeout=180, check=False,
    )
    if rejection:
        if result.returncode == 0:
            raise AssertionError(f"{language} accepted a tampered packet")
        return None
    if result.returncode:
        raise RuntimeError(f"{language} adapter failed:\n{result.stderr}\n{result.stdout}")
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError(f"{language} did not return JSON:\n{result.stdout}") from exc


def main():
    vectors = json.loads((ROOT / "docs/protocols/agent-mail/1.0.vectors.json").read_text())
    expected = vectors["envelopes"][vectors["encryptions"]["original"]["letter"]]
    packets = []
    for sender in ADAPTERS:
        pair = [invoke(sender, {"op": "seal"}) for _ in range(2)]
        if pair[0]["enc"] == pair[1]["enc"]:
            raise AssertionError(f"{sender} reused an encapsulation")
        packets.extend((sender, packet) for packet in pair)
        print(f"{sender}: fresh production encapsulations generated", flush=True)

    opened = 0
    for sender, packet in packets:
        for recipient in ADAPTERS:
            actual = invoke(recipient, {"op": "open", "packet": packet})
            if actual != expected:
                raise AssertionError(f"{sender} -> {recipient}: signed letter changed")
            opened += 1

    tampered_ciphertext = copy.deepcopy(packets[0][1])
    encoded = tampered_ciphertext["ciphertext"]
    raw = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    raw[0] ^= 1
    tampered_ciphertext["ciphertext"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    tampered_header = copy.deepcopy(packets[0][1])
    tampered_header["header"]["expires_at"] += 1
    rejected = 0
    for packet in (tampered_ciphertext, tampered_header):
        for recipient in ADAPTERS:
            invoke(recipient, {"op": "open", "packet": packet}, rejection=True)
            rejected += 1
    print(f"PASS: {opened} cross-SDK decryptions, 6 fresh packets, {rejected} tamper rejections.")


if __name__ == "__main__":
    main()
