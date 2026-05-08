from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import os
import struct
import time
from pathlib import Path

from ipv8.community import Community
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload_headers import (
    BinMemberAuthenticationPayload,
    GlobalTimeDistributionPayload,
)
from ipv8_service import IPv8


COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811"
    "da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)
DIFFICULTY_BITS = 28

DEFAULT_EMAIL = "M.Trapasso-1@student.tudelft.nl"
DEFAULT_GITHUB_URL = "https://github.com/RiventingCube/blockchain_engineering.git"
DEFAULT_NONCE = 491201209
DEFAULT_KEY_FILE = Path("private_key.pem")


def log(message: str) -> None:
    print(message, flush=True)


@vp_compile
class SubmissionPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


@vp_compile
class ResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


def validate_inputs(email: str, github_url: str, nonce: int) -> None:
    email_bytes = email.encode("utf-8")
    github_url_bytes = github_url.encode("utf-8")

    if "\n" in email or "\r" in email:
        raise ValueError("email must not contain newlines")
    if not email or len(email_bytes) > 254:
        raise ValueError("email must be non-empty and <= 254 UTF-8 bytes")
    if not email.strip().lower().endswith(("@tudelft.nl", "@student.tudelft.nl")):
        raise ValueError("email must end in @tudelft.nl or @student.tudelft.nl")

    if not github_url or len(github_url_bytes) > 512:
        raise ValueError("github URL must be non-empty and <= 512 UTF-8 bytes")
    if any(ord(char) <= 32 or ord(char) == 127 for char in github_url):
        raise ValueError("github URL must not contain whitespace/control characters")

    if nonce < 0 or nonce > 2**63 - 1:
        raise ValueError("nonce must satisfy 0 <= nonce <= 2^63 - 1")


def digest_for_nonce(email: str, github_url: str, nonce: int) -> bytes:
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    return hashlib.sha256(prefix + struct.pack(">q", nonce)).digest()


def pow_is_valid(digest: bytes) -> bool:
    return digest[:3] == b"\x00\x00\x00" and digest[3] < 16


def mine_pow(email: str, github_url: str, start_nonce: int = 0) -> tuple[int, str]:
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    sha_prefix = hashlib.sha256(prefix)
    pack_nonce = struct.Struct(">q").pack
    nonce = start_nonce
    started_at = time.monotonic()

    log(f"[MINER] Mining {DIFFICULTY_BITS}-bit PoW from nonce {start_nonce}...")
    while nonce <= 2**63 - 1:
        hasher = sha_prefix.copy()
        hasher.update(pack_nonce(nonce))
        digest = hasher.digest()
        if pow_is_valid(digest):
            log(f"[MINER] Found nonce: {nonce}")
            log(f"[MINER] Digest: {digest.hex()}")
            return nonce, digest.hex()

        nonce += 1
        if nonce % 1_000_000 == 0:
            elapsed = max(time.monotonic() - started_at, 0.001)
            log(f"[MINER] Checked {nonce:,} nonces ({nonce / elapsed:,.0f} hashes/sec)")

    raise RuntimeError("searched the full nonce range without a valid solution")


class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponsePayload.msg_id, self.on_response_packet)
        self.response_received: asyncio.Event = asyncio.Event()
        self.response: tuple[bool, str] | None = None

    def is_server_peer(self, peer) -> bool:
        return peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY

    def server_peer(self):
        return next((peer for peer in self.get_peers() if self.is_server_peer(peer)), None)

    def send_submission(self, email: str, github_url: str, nonce: int) -> bool:
        peer = self.server_peer()
        if peer is None:
            return False

        log(f"[SYSTEM] Server discovered at {peer.address}. Sending signed submission.")
        self.ez_send(peer, SubmissionPayload(email, github_url, nonce))
        return True

    def on_response_packet(self, source_address, data: bytes) -> None:
        auth, _ = self.serializer.unpack_serializable(
            BinMemberAuthenticationPayload,
            data,
            offset=23,
        )

        # Important: filter raw public key before IPv8 tries to decode unsupported peer curves.
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return

        signature_valid, remainder = self._verify_signature(auth, data)
        if not signature_valid:
            log("[WARNING] Ignoring server response with invalid signature.")
            return

        _, payload = self.serializer.unpack_serializable_list(
            [GlobalTimeDistributionPayload, ResponsePayload],
            remainder,
            offset=23,
        )

        status = "OK" if payload.success else "REJECTED"
        log(f"[SERVER RESPONSE] {status}: {payload.message}")
        self.response = (payload.success, payload.message)
        self.response_received.set()


async def run_client(
    email: str,
    github_url: str,
    nonce: int,
    key_file: Path,
    port: int,
    timeout: float,
    retry_interval: float,
    max_submissions: int,
) -> tuple[bool, str]:
    validate_inputs(email, github_url, nonce)
    digest = digest_for_nonce(email, github_url, nonce)
    if not pow_is_valid(digest):
        raise ValueError(f"invalid PoW nonce; digest={digest.hex()}")

    logging.disable(logging.CRITICAL)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_log_level("CRITICAL")
    builder.add_key("my_identity", "curve25519", str(key_file))
    builder.add_overlay(
        "Lab1Community",
        "my_identity",
        [WalkerDefinition(Strategy.RandomWalk, 1000, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"Lab1Community": Lab1Community},
    )
    await ipv8.start()

    try:
        if key_file.exists():
            os.chmod(key_file, 0o600)

        overlay = ipv8.get_overlay(Lab1Community)
        public_key = overlay.my_peer.public_key.key_to_bin().hex()
        log(f"[SYSTEM] IPv8 started on UDP port {port}.")
        log(f"[SYSTEM] Key file: {key_file}")
        log(f"[SYSTEM] Your public key: {public_key}")
        log("[SYSTEM] Discovering verified lab server peer...")

        started_at = time.monotonic()
        last_send_at = 0.0
        submissions = 0

        while time.monotonic() - started_at < timeout:
            if overlay.response_received.is_set():
                assert overlay.response is not None
                return overlay.response

            now = time.monotonic()
            can_send = submissions == 0 or now - last_send_at >= retry_interval
            if submissions < max_submissions and can_send:
                sent = overlay.send_submission(email, github_url, nonce)
                if sent:
                    submissions += 1
                    last_send_at = now
                    log(f"[SYSTEM] Submission attempt {submissions}/{max_submissions}.")
                else:
                    log(f"[SYSTEM] Waiting for server peer... known peers: {len(overlay.get_peers())}")

            await asyncio.sleep(2)

        raise TimeoutError(
            f"timed out after {timeout:.0f}s; submissions sent: {submissions}"
        )
    finally:
        await ipv8.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 1 IPv8 Proof-of-Work client")
    parser.add_argument("--email", default=DEFAULT_EMAIL)
    parser.add_argument("--github-url", default=DEFAULT_GITHUB_URL)
    parser.add_argument("--nonce", type=int, default=DEFAULT_NONCE)
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE)
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--retry-interval", type=float, default=30.0)
    parser.add_argument("--max-submissions", type=int, default=5)
    parser.add_argument("--mine", action="store_true", help="Mine a fresh nonce before submitting")
    parser.add_argument("--verify-only", action="store_true", help="Verify inputs/nonce locally and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    nonce = args.nonce
    if args.mine:
        nonce, _ = mine_pow(args.email, args.github_url)

    validate_inputs(args.email, args.github_url, nonce)
    digest = digest_for_nonce(args.email, args.github_url, nonce)
    log(f"[MINER] Nonce: {nonce}")
    log(f"[MINER] Digest: {digest.hex()}")
    log(f"[MINER] Valid PoW: {pow_is_valid(digest)}")

    if not pow_is_valid(digest):
        return 1
    if args.verify_only:
        return 0

    success, message = asyncio.run(
        run_client(
            args.email,
            args.github_url,
            nonce,
            args.key_file,
            args.port,
            args.timeout,
            args.retry_interval,
            args.max_submissions,
        )
    )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
