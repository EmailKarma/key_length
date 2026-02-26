#!/usr/bin/env python3
"""
DKIM Key Length Checker

Usage:
  python3 key_length.py <selector> <domain>
"""

import argparse
import json
import os
import re
import subprocess
import tempfile
from typing import Optional

import dns.resolver


def build_dkim_name(selector: str, domain: str) -> str:
    return f"{selector}._domainkey.{domain}".strip(".")


def get_dkim_record(selector: str, domain: str, nameserver: Optional[str], timeout: float) -> str:
    qname = build_dkim_name(selector, domain)

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout

    if nameserver:
        resolver.nameservers = [nameserver]

    answers = resolver.resolve(qname, "TXT")

    records = []
    for rdata in answers:
        parts = []
        for part in getattr(rdata, "strings", []):
            if isinstance(part, bytes):
                parts.append(part.decode("utf-8", errors="replace"))
            else:
                parts.append(str(part))
        records.append("".join(parts))

    for rec in records:
        if "p=" in rec:
            return rec

    if not records:
        raise RuntimeError("No TXT records found")

    return records[0]


def extract_p_value(dkim_record: str) -> str:
    match = re.search(r"(?:^|;)\s*p=([A-Za-z0-9+/=]+)\s*(?:;|$)", dkim_record)
    if not match:
        raise RuntimeError("Could not find p= value in DKIM record")

    pval = match.group(1).strip()

    if not pval:
        raise RuntimeError("p= value is empty")

    return pval


def pem_wrap_public_key(public_key_b64: str) -> str:
    wrapped = "\n".join(public_key_b64[i:i + 64] for i in range(0, len(public_key_b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n"


def openssl_rsa_key_length_from_pem(pem: str, openssl_bin: str) -> int:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w", encoding="utf-8") as tmp:
        tmp.write(pem)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [openssl_bin, "rsa", "-pubin", "-text", "-noout", "-in", tmp_path],
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip())

        match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", proc.stdout)
        if not match:
            raise RuntimeError("Could not determine key length from OpenSSL output")

        return int(match.group(1))

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Fetch DKIM DNS TXT record and report RSA public key length."
    )

    # Positional arguments
    parser.add_argument("selector", help="DKIM selector")
    parser.add_argument("domain", help="Domain name")

    # Optional flags
    parser.add_argument("-n", "--nameserver", help="Optional DNS resolver IP")
    parser.add_argument("--timeout", type=float, default=4.0, help="DNS timeout in seconds")
    parser.add_argument("--openssl", default="openssl", help="Path to openssl binary")
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    args = parser.parse_args()

    try:
        dkim_record = get_dkim_record(args.selector, args.domain, args.nameserver, args.timeout)
        public_key_b64 = extract_p_value(dkim_record)
        public_key_pem = pem_wrap_public_key(public_key_b64)
        bits = openssl_rsa_key_length_from_pem(public_key_pem, args.openssl)

        if args.output == "json":
            result = {
                "selector": args.selector,
                "domain": args.domain,
                "dkim_record": dkim_record,
                "public_key_pem": public_key_pem.strip(),
                "key_length_bits": bits,
                "key_length_label": f"{bits}b"
            }
            print(json.dumps(result, indent=2))

        else:
            print("DKIM Public Key (PEM):")
            print(public_key_pem.strip())
            print()
            print(f"DKIM Public Key Length: {bits}b")

        return 0

    except Exception as e:
        if args.output == "json":
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())