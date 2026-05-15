from __future__ import annotations

import argparse
import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ipv8.community import Community
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8


COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011"
    "a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)

GROUP_SIZE = 3
ROUNDS = 3
SIGNATURE_LENGTH = 64


def log(message: str) -> None:
    print(message, flush=True)


class RegisterGroup(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]


class RegisterReply(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]


class ChallengeRequest(VariablePayloadWID):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]


class ChallengeReply(VariablePayloadWID):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]


class SignatureBundle(VariablePayloadWID):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]


class RoundReply(VariablePayloadWID):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


class RoundSignal(VariablePayloadWID):
    """Peer protocol: empty nonce means "you submit this round"; otherwise sign it."""

    msg_id = 10
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "nonce"]


class SignatureShare(VariablePayloadWID):
    msg_id = 11
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "signature"]


@dataclass
class ActiveRound:
    round_number: int
    challenge_seen: asyncio.Event = field(default_factory=asyncio.Event)
    enough_signatures: asyncio.Event = field(default_factory=asyncio.Event)
    result_seen: asyncio.Event = field(default_factory=asyncio.Event)
    nonce: bytes = b""
    deadline: float = 0.0
    signatures: dict[int, bytes] = field(default_factory=dict)
    result: RoundReply | None = None


class Lab2Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.add_message_handler(RegisterReply, self.on_register_reply)
        self.add_message_handler(ChallengeReply, self.on_challenge_reply)
        self.add_message_handler(RoundReply, self.on_round_reply)
        self.add_message_handler(RoundSignal, self.on_round_signal)
        self.add_message_handler(SignatureShare, self.on_signature_share)

        self.member_keys: list[bytes] = []
        self.my_key_bin: bytes = b""
        self.my_index: int = -1
        self.group_id: str = ""

        self.registration_done = asyncio.Event()
        self.registration_ok = False
        self.registration_message = ""

        self.active_rounds: dict[int, ActiveRound] = {}
        self.started_submitter_rounds: set[int] = set()
        self.completed_rounds = 0
        self.finished = asyncio.Event()
        self.debug_peers = False

    def configure(self, member_keys: list[bytes], group_id: str = "", debug_peers: bool = False) -> None:
        if len(member_keys) != GROUP_SIZE:
            raise ValueError("exactly 3 member keys are required")

        self.member_keys = member_keys
        self.my_key_bin = self.my_peer.public_key.key_to_bin()
        self.group_id = group_id
        self.debug_peers = debug_peers

        try:
            self.my_index = member_keys.index(self.my_key_bin)
        except ValueError as exc:
            raise ValueError("the configured private key is not one of the 3 group keys") from exc

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY

    def is_member(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() in self.member_keys

    def peer_for_key(self, key: bytes) -> Peer | None:
        return next((peer for peer in self.get_peers() if peer.public_key.key_to_bin() == key), None)

    def server_peer(self) -> Peer | None:
        return next((peer for peer in self.get_peers() if self.is_server(peer)), None)

    async def wait_for_server(self, timeout: float) -> Peer:
        started = time.monotonic()
        last_log = 0.0
        while time.monotonic() - started < timeout:
            peer = self.server_peer()
            if peer is not None:
                log(f"[network] verified server at {peer.address}")
                return peer

            now = time.monotonic()
            if now - last_log >= 5.0:
                last_log = now
                log(f"[network] waiting for server; known peers={len(self.get_peers())}")
            await asyncio.sleep(0.2)

        raise TimeoutError("server peer was not discovered")

    async def wait_for_teammates(self, timeout: float) -> None:
        wanted = {key for key in self.member_keys if key != self.my_key_bin}
        started = time.monotonic()
        last_log = 0.0

        while time.monotonic() - started < timeout:
            found = {peer.public_key.key_to_bin() for peer in self.get_peers()} & wanted
            if found == wanted:
                log("[network] all teammates discovered")
                return

            now = time.monotonic()
            if now - last_log >= 5.0:
                last_log = now
                known = len(self.get_peers())
                log(f"[network] waiting for teammates ({len(found)}/{len(wanted)} found; known peers={known})")
                if self.debug_peers:
                    self.print_peer_debug(found, wanted)
            await asyncio.sleep(0.2)

        missing = [key.hex() for key in sorted(wanted - found)]
        raise TimeoutError(f"teammate peer(s) not discovered: {', '.join(missing)}")

    def print_peer_debug(self, found: set[bytes], wanted: set[bytes]) -> None:
        for index, key in enumerate(self.member_keys, start=1):
            marker = "me"
            if key != self.my_key_bin:
                marker = "found" if key in found else "missing"
            log(f"[debug] member{index} {marker}: {key.hex()}")

        peers = self.get_peers()
        if not peers:
            log("[debug] no IPv8 peers are visible yet")
            return

        for peer in peers[:10]:
            key = peer.public_key.key_to_bin()
            if key == SERVER_PUBLIC_KEY:
                label = "server"
            elif key in wanted:
                label = "teammate"
            else:
                label = "other"
            log(f"[debug] visible {label} at {peer.address}: {key.hex()}")

    async def register_group(self, timeout: float, retry_interval: float) -> None:
        server = await self.wait_for_server(timeout)
        payload = RegisterGroup(*self.member_keys)
        started = time.monotonic()
        attempts = 0

        while time.monotonic() - started < timeout:
            if self.registration_done.is_set():
                break

            attempts += 1
            log(f"[registration] sending request attempt {attempts}")
            self.ez_send(server, payload)

            try:
                await asyncio.wait_for(self.registration_done.wait(), timeout=retry_interval)
            except asyncio.TimeoutError:
                continue

        if not self.registration_done.is_set():
            raise TimeoutError("registration timed out")
        if not self.registration_ok:
            raise RuntimeError(f"registration failed: {self.registration_message}")

        log(f"[registration] group_id={self.group_id}")

    async def act_as_submitter(self, round_number: int) -> bool:
        if round_number in self.started_submitter_rounds:
            return False
        self.started_submitter_rounds.add(round_number)

        if round_number < 1 or round_number > ROUNDS:
            return False

        submitter_index = round_number - 1
        if submitter_index != self.my_index:
            log(f"[round {round_number}] trigger ignored; member {submitter_index + 1} is submitter")
            return False
        if not self.group_id:
            log(f"[round {round_number}] cannot request a challenge without a group_id")
            return False

        await self.wait_for_server(timeout=20.0)
        await self.wait_for_teammates(timeout=20.0)

        state = ActiveRound(round_number)
        self.active_rounds[round_number] = state

        log(f"[round {round_number}] requesting server challenge")
        await self.request_challenge_until_seen(state)
        if not state.nonce:
            return False

        own_signature = default_eccrypto.create_signature(self.my_peer.key, state.nonce)
        state.signatures[self.my_index] = own_signature
        state.enough_signatures.clear()

        log(f"[round {round_number}] challenge received; collecting signatures")
        await self.collect_signatures(state)
        if len(state.signatures) != GROUP_SIZE:
            log(f"[round {round_number}] missing signatures before deadline")
            return False

        log(f"[round {round_number}] submitting bundle")
        await self.submit_until_result(state)

        if state.result and state.result.success:
            self.completed_rounds = max(self.completed_rounds, state.result.rounds_completed)
            if state.result.rounds_completed >= ROUNDS:
                self.finished.set()
            else:
                await self.trigger_round(state.result.rounds_completed + 1)
            return True

        return False

    async def request_challenge_until_seen(self, state: ActiveRound) -> None:
        request = ChallengeRequest(self.group_id)
        started = time.monotonic()

        while not state.challenge_seen.is_set() and time.monotonic() - started < 8.0:
            server = self.server_peer()
            if server is not None:
                self.ez_send(server, request)

            try:
                await asyncio.wait_for(state.challenge_seen.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                pass

            if state.result is not None and not state.result.success:
                return

        if not state.challenge_seen.is_set():
            log(f"[round {state.round_number}] no challenge response received")

    async def collect_signatures(self, state: ActiveRound) -> None:
        signal = RoundSignal(self.group_id, state.round_number, state.nonce)
        started = time.monotonic()

        while len(state.signatures) < GROUP_SIZE:
            now = time.time()
            if state.deadline and now >= state.deadline - 0.15:
                break
            if time.monotonic() - started > 8.5:
                break

            for index, key in enumerate(self.member_keys):
                if index == self.my_index or index in state.signatures:
                    continue
                peer = self.peer_for_key(key)
                if peer is not None:
                    self.ez_send(peer, signal)

            if len(state.signatures) >= GROUP_SIZE:
                break

            try:
                await asyncio.wait_for(state.enough_signatures.wait(), timeout=0.15)
            except asyncio.TimeoutError:
                pass

    async def submit_until_result(self, state: ActiveRound) -> None:
        signatures = [state.signatures[index] for index in range(GROUP_SIZE)]
        bundle = SignatureBundle(self.group_id, state.round_number, *signatures)
        started = time.monotonic()

        while not state.result_seen.is_set():
            now = time.time()
            if state.deadline and now >= state.deadline + 0.8:
                break
            if time.monotonic() - started > 9.5:
                break

            server = self.server_peer()
            if server is not None:
                self.ez_send(server, bundle)

            try:
                await asyncio.wait_for(state.result_seen.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                pass

    async def trigger_round(self, round_number: int) -> None:
        if round_number > ROUNDS:
            return

        next_key = self.member_keys[round_number - 1]
        peer = self.peer_for_key(next_key)
        if peer is None:
            log(f"[round {round_number}] next submitter is not currently visible")
            return

        log(f"[round {round_number}] triggering member {round_number} as submitter")
        trigger = RoundSignal(self.group_id, round_number, b"")
        for _ in range(6):
            self.ez_send(peer, trigger)
            await asyncio.sleep(0.08)

    async def reply_with_signature(self, peer: Peer, group_id: str, round_number: int, nonce: bytes) -> None:
        signature = default_eccrypto.create_signature(self.my_peer.key, nonce)
        reply = SignatureShare(group_id, round_number, signature)

        for _ in range(3):
            self.ez_send(peer, reply)
            await asyncio.sleep(0.05)

    @lazy_wrapper(RegisterReply)
    def on_register_reply(self, peer: Peer, payload: RegisterReply) -> None:
        if not self.is_server(peer):
            return

        self.registration_ok = payload.success
        self.registration_message = payload.message
        if payload.success:
            self.group_id = payload.group_id
        status = "ok" if payload.success else "rejected"
        log(f"[registration] {status}: {payload.message}")
        self.registration_done.set()

    @lazy_wrapper(ChallengeReply)
    def on_challenge_reply(self, peer: Peer, payload: ChallengeReply) -> None:
        if not self.is_server(peer):
            return

        state = self.active_rounds.get(payload.round_number)
        if state is None:
            log(f"[round {payload.round_number}] challenge received but I am not submitter")
            return

        if state.challenge_seen.is_set():
            return

        state.nonce = payload.nonce
        state.deadline = payload.deadline
        log(
            f"[round {payload.round_number}] nonce={payload.nonce.hex()[:16]}... "
            f"deadline={payload.deadline:.3f}"
        )
        state.challenge_seen.set()

    @lazy_wrapper(RoundReply)
    def on_round_reply(self, peer: Peer, payload: RoundReply) -> None:
        if not self.is_server(peer):
            return

        state = self.active_rounds.get(payload.round_number)
        if state is not None and not state.result_seen.is_set():
            state.result = payload
            state.result_seen.set()

        status = "accepted" if payload.success else "rejected"
        log(
            f"[round {payload.round_number}] {status}: {payload.message} "
            f"({payload.rounds_completed}/{ROUNDS})"
        )

        if payload.success and payload.rounds_completed >= ROUNDS:
            self.completed_rounds = max(self.completed_rounds, payload.rounds_completed)
            self.finished.set()
        elif payload.success:
            self.completed_rounds = max(self.completed_rounds, payload.rounds_completed)
        elif not payload.success and (
            "budget exceeded" in payload.message
            or "group already completed" in payload.message
            or "no active challenge" in payload.message
        ):
            self.finished.set()

    @lazy_wrapper(RoundSignal)
    def on_round_signal(self, peer: Peer, payload: RoundSignal) -> None:
        if not self.is_member(peer):
            log("[peer] ignoring round signal from non-member")
            return

        if self.group_id and payload.group_id != self.group_id:
            log("[peer] ignoring round signal for a different group")
            return
        if not self.group_id:
            self.group_id = payload.group_id

        if payload.round_number < 1 or payload.round_number > ROUNDS:
            return

        submitter_key = self.member_keys[payload.round_number - 1]
        sender_key = peer.public_key.key_to_bin()

        if payload.nonce == b"":
            if submitter_key == self.my_key_bin:
                log(f"[round {payload.round_number}] submitter trigger received")
                self.register_anonymous_task(
                    f"submitter-round-{payload.round_number}",
                    self.act_as_submitter,
                    payload.round_number,
                )
            return

        if sender_key != submitter_key:
            log(f"[round {payload.round_number}] ignoring nonce from wrong submitter")
            return
        if len(payload.nonce) != 32:
            log(f"[round {payload.round_number}] ignoring malformed nonce")
            return

        log(f"[round {payload.round_number}] signing nonce for submitter")
        self.register_anonymous_task(
            f"signature-reply-round-{payload.round_number}",
            self.reply_with_signature,
            peer,
            payload.group_id,
            payload.round_number,
            payload.nonce,
        )

    @lazy_wrapper(SignatureShare)
    def on_signature_share(self, peer: Peer, payload: SignatureShare) -> None:
        if not self.is_member(peer):
            log("[peer] ignoring signature from non-member")
            return
        if payload.group_id != self.group_id:
            return

        state = self.active_rounds.get(payload.round_number)
        if state is None:
            return
        if len(payload.signature) != SIGNATURE_LENGTH:
            log(f"[round {payload.round_number}] ignoring malformed signature")
            return

        sender_key = peer.public_key.key_to_bin()
        sender_index = self.member_keys.index(sender_key)
        if sender_index in state.signatures:
            return

        state.signatures[sender_index] = payload.signature
        log(f"[round {payload.round_number}] received signature from member {sender_index + 1}")
        if len(state.signatures) == GROUP_SIZE:
            state.enough_signatures.set()


def read_private_public_key(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} does not exist; use the same private key file that passed Lab 1"
        )
    with path.open("rb") as handle:
        return default_eccrypto.key_from_private_bin(handle.read()).pub().key_to_bin()


def parse_hex_key(value: str, flag_name: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{flag_name} is not valid hex") from exc
    if not key:
        raise argparse.ArgumentTypeError(f"{flag_name} must not be empty")
    return key


def default_key_file() -> Path:
    lab1_key = Path("A1/marco/private_key.pem")
    return lab1_key if lab1_key.exists() else Path("private_key.pem")


def build_member_order(args: argparse.Namespace, own_key: bytes) -> list[bytes]:
    member1 = parse_hex_key(args.member1, "--member1") if args.member1 else None
    member2 = parse_hex_key(args.member2, "--member2") if args.member2 else None
    member3 = parse_hex_key(args.member3, "--member3") if args.member3 else None

    peer2 = parse_hex_key(args.peer2, "--peer2") if args.peer2 else None
    peer3 = parse_hex_key(args.peer3, "--peer3") if args.peer3 else None

    if args.role in ("coordinator", "member1"):
        member1 = member1 or own_key
        member2 = member2 or peer2
        member3 = member3 or peer3
    elif args.role == "member2":
        member2 = member2 or own_key
    elif args.role == "member3":
        member3 = member3 or own_key

    if None in (member1, member2, member3):
        raise ValueError(
            "provide the canonical order with --member1, --member2, and --member3 "
            "(coordinator may use --peer2 and --peer3 instead)"
        )

    keys = [member1, member2, member3]
    if len(set(keys)) != GROUP_SIZE:
        raise ValueError("the 3 member public keys must be distinct")
    if own_key not in keys:
        raise ValueError("your private key's public key is not in the member list")

    return keys


async def run(args: argparse.Namespace) -> int:
    own_public_key = read_private_public_key(args.key_file)
    member_keys = build_member_order(args, own_public_key)
    own_index = member_keys.index(own_public_key)
    autostart = args.start or args.role == "coordinator" or args.role == "member1"

    logging.disable(logging.CRITICAL)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.set_log_level("CRITICAL")
    builder.add_key("lab2_key", "curve25519", str(args.key_file))
    builder.add_overlay(
        "Lab2Community",
        "lab2_key",
        [WalkerDefinition(Strategy.RandomWalk, 1000, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()

    community: Lab2Community = ipv8.get_overlay(Lab2Community)
    community.configure(member_keys, group_id=args.group_id, debug_peers=args.debug_peers)

    log(f"[system] UDP port: {args.port}")
    log(f"[system] public key: {own_public_key.hex()}")
    log(f"[system] member index: {own_index + 1}")

    try:
        if autostart:
            if not community.group_id:
                await community.register_group(args.discovery_timeout, args.register_retry)
            else:
                await community.wait_for_server(args.discovery_timeout)

            await community.wait_for_teammates(args.discovery_timeout)
            await community.act_as_submitter(1)
        else:
            log("[system] ready; waiting for peer round signals")
            await community.wait_for_server(args.discovery_timeout)
            try:
                await community.wait_for_teammates(args.discovery_timeout)
            except TimeoutError as exc:
                log(f"[network] {exc}")

        try:
            await asyncio.wait_for(community.finished.wait(), timeout=args.run_timeout)
        except asyncio.TimeoutError:
            if community.completed_rounds:
                log("[system] no final server result reached this node before timeout")
                return 0
            log("[system] run timed out")
            return 1

        return 0 if community.completed_rounds >= ROUNDS or community.finished.is_set() else 1
    finally:
        await ipv8.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 2 coordinated group signing client")
    parser.add_argument(
        "--role",
        choices=["coordinator", "member", "member1", "member2", "member3"],
        default="member",
        help="coordinator/member1 starts registration and round 1; others wait for triggers",
    )
    parser.add_argument("--key-file", "--key", type=Path, default=default_key_file())
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--group-id", default="", help="reuse an existing registered group")

    parser.add_argument("--member1", default="", help="canonical member 1 public key hex")
    parser.add_argument("--member2", default="", help="canonical member 2 public key hex")
    parser.add_argument("--member3", default="", help="canonical member 3 public key hex")
    parser.add_argument("--peer2", default="", help="coordinator shorthand for member 2 public key hex")
    parser.add_argument("--peer3", default="", help="coordinator shorthand for member 3 public key hex")

    parser.add_argument("--start", action="store_true", help="start registration/round 1 from this node")
    parser.add_argument("--discovery-timeout", type=float, default=120.0)
    parser.add_argument("--register-retry", type=float, default=2.0)
    parser.add_argument("--run-timeout", type=float, default=180.0)
    parser.add_argument("--debug-peers", action="store_true", help="print visible peer public keys while waiting")
    return parser.parse_args()


def main() -> int:
    try:
        return asyncio.run(run(parse_args()))
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        log(f"[error] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
