"""
Usage:
    python lab1_pow_client.py --email <tudelft email> --github <repo url>

Options:
    --email      Your TU Delft email address
    --github     Your public GitHub repo URL
    --key        Path to your .pem key file (default: my_key.pem, created if missing)
    --nonce      Skip mining and use this nonce (for testing)
    --port       UDP port to bind (default: 8090, change if already in use)
"""
import argparse
import asyncio
import hashlib
import logging
import os
import struct
import sys
import time
from threading import Thread, Event
from multiprocessing import cpu_count

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import VariablePayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8

COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY_HEX = ("4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb")
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)
DIFFICULTY_BITS = 28

def check_difficulty(digest: bytes, bits: int) -> bool:
    full_bytes, remainder = divmod(bits, 8)
    for i in range(full_bytes):
        if digest[i] != 0:
            return False
    if remainder:
        mask = 0xFF >> remainder
        if digest[full_bytes] & ~mask:
            return False
    return True


def mine_range(email: bytes, github: bytes, start: int, step: int,
               result_holder: list, stop_event: Event, progress_interval: int = 1_000_000):
    prefix = email + b"\n" + github + b"\n"
    nonce = start
    checked = 0
    t0 = time.time()

    while not stop_event.is_set():
        data = prefix + struct.pack(">q", nonce)
        digest = hashlib.sha256(data).digest()
        if check_difficulty(digest, DIFFICULTY_BITS):
            result_holder[0] = nonce
            stop_event.set()
            return
        nonce += step
        checked += 1
        if checked % progress_interval == 0:
            elapsed = time.time() - t0
            rate = checked / elapsed if elapsed > 0 else 0
            print(f"  [thread-{start % step}] {checked:,} hashes, {rate:,.0f} H/s, nonce={nonce:,}", flush=True)
        if nonce >= 2**63:
            break


def compute_pow(email: str, github_url: str) -> int:
    num_threads = max(1, cpu_count())

    email_bytes = email.encode("utf-8")
    github_bytes = github_url.encode("utf-8")

    print(f"[PoW] Starting mining with {num_threads} thread(s)...")
    print(f"      email:  {email}")
    print(f"      github: {github_url}")

    stop_event = Event()
    result_holder = [None]
    threads = []

    t_start = time.time()
    for i in range(num_threads):
        t = Thread(
            target=mine_range,
            args=(email_bytes, github_bytes, i, num_threads, result_holder, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - t_start
    nonce = result_holder[0]
    if nonce is None:
        raise RuntimeError("Mining exhausted search space without finding a solution.")

    data = email_bytes + b"\n" + github_bytes + b"\n" + struct.pack(">q", nonce)
    digest = hashlib.sha256(data).hexdigest()
    print(f"\n[Found nonce: {nonce}  (after {elapsed:.1f}s)")
    print(f"      SHA-256: {digest}")
    return nonce

class SubmissionPayload(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


class ResponsePayload(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponsePayload, self.on_response)
        self._email = None
        self._github_url = None
        self._nonce = None
        self._server_peer = None
        self._submitted = False
        self._done_event = asyncio.Event()

    def configure(self, email: str, github_url: str, nonce: int) -> None:
        self._email = email
        self._github_url = github_url
        self._nonce = nonce

    def started(self) -> None:
        self.register_task("find_server", self._find_and_send, interval=2.0, delay=1.0)

    def _find_and_send(self) -> None:
        if self._submitted:
            return
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self._server_peer = peer
                print(f"[IPv8] Found server peer: {peer.address}")
                self._submit()
                return
        print(f"[IPv8] Waiting for server peer... ({len(self.get_peers())} peers known)")

    def _submit(self) -> None:
        if self._submitted:
            return
        self._submitted = True
        print("[IPv8] Sending submission to server...")
        payload = SubmissionPayload(
            email=self._email,
            github_url=self._github_url,
            nonce=self._nonce,
        )
        self.ez_send(self._server_peer, payload)
        print("[IPv8] Submission sent. Waiting for response...")

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"[WARN] Ignoring response from unknown peer {peer.address}")
            return
        status = "SUCCESS" if payload.success else "REJECTED"
        print(f"\n{'='*60}")
        print(f"  Server Response: {status}")
        print(f"  Message: {payload.message}")
        print(f"{'='*60}\n")
        self._done_event.set()


def load_or_create_key(path: str):
    from ipv8.keyvault.crypto import default_eccrypto

    if os.path.exists(path):
        print(f"[Key] Loading existing key from {path}")
        with open(path, "rb") as f:
            key = default_eccrypto.key_from_private_bin(f.read())
    else:
        print(f"[Key] Generating new key pair, saving to {path}")
        key = default_eccrypto.generate_key("curve25519")
        with open(path, "wb") as f:
            f.write(key.key_to_bin())
        print(f"[Key] Public key (hex): {key.pub().key_to_bin().hex()}")
        
    print(f"[Key] Public key (hex): {key.pub().key_to_bin().hex()}")
    return key


async def run(email: str, github_url: str, key_path: str, nonce: int = None, port: int = 8090):
    if nonce is None:
        nonce = compute_pow(email, github_url)
    else:
        print(f"[PoW] Using pre-computed nonce: {nonce}")

    load_or_create_key(key_path)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", key_path)
    builder.add_overlay(
        "Lab1Community",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )
    config = builder.finalize()

    for iface in config.get("interfaces", []):
        iface["ip"] = "0.0.0.0"
        iface["port"] = port

    ipv8 = IPv8(config, extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    print(f"[IPv8] Started on 0.0.0.0:{port}. Discovering peers...")

    community: Lab1Community = ipv8.get_overlay(Lab1Community)
    community.configure(email, github_url, nonce)

    try:
        await asyncio.wait_for(community._done_event.wait(), timeout=300)
    except asyncio.TimeoutError:
        print("\n[TIMEOUT] No response received within 5 minutes.")
    finally:
        await ipv8.stop()

def main():
    parser = argparse.ArgumentParser(description="Lab 1: IPv8 Proof of Work Client")
    parser.add_argument("--email", required=True, help="Your TU Delft email address")
    parser.add_argument("--github", required=True, help="Your public GitHub repo URL")
    parser.add_argument("--key", default="my_key.pem", help="Path to .pem key file (default: my_key.pem)")
    parser.add_argument("--nonce", type=int, default=None, help="Skip mining and use this nonce")
    parser.add_argument("--port", type=int, default=8090, help="UDP port to bind (default: 8090)")
    args = parser.parse_args()

    email = args.email.strip().lower()
    github_url = args.github.strip()
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(run(email, github_url, args.key, args.nonce, args.port))


if __name__ == "__main__":
    main()