# Lab 2 Coordinator

This document explains `main.py`, the Lab 2 coordinator client.

`main.py` is intended to be run by member 1. Its responsibilities are:

1. Discovering the Lab 2 server through IPv8.
2. Verifying the server by matching the published server public key.
3. Registering the group with the canonical key order:
   - member 1: coordinator
   - member 2
   - member 3
4. Waiting until member 2 and member 3 are discovered by public key.
5. Requesting the round 1 challenge.
6. Signing the nonce locally.
7. Sending the nonce to member 2 and member 3.
8. Collecting their signatures.
9. Submitting the round 1 signature bundle to the server.
10. Triggering member 2 to submit round 2.
11. Signing nonce requests for member 2 and member 3 during rounds 2 and 3.

The server-side payloads follow the assignment specification exactly:

| Message | ID |
|---|---:|
| Register group | 1 |
| Register response | 2 |
| Challenge request | 3 |
| Challenge response | 4 |
| Signature bundle | 5 |
| Round result | 6 |

## Internal Peer Protocol

`main.py` uses two internal authenticated IPv8 messages to coordinate with the other group members:

| Message | ID | Fields |
|---|---:|---|
| Round signal | 10 | `group_id`, `round_number`, `nonce` |
| Signature share | 11 | `group_id`, `round_number`, `signature` |

For message `10`:

- If `nonce` is empty, `main.py` is telling the selected member to act as submitter for that round.
- If `nonce` is 32 bytes, `main.py` is asking that member to sign the nonce.

For message `11`, `main.py` receives a teammate signature and stores it in the correct signature slot.

All messages are sent with `ez_send`, so IPv8 adds authentication and signatures to the packets.

## Signature Order

The signature bundle must match the registration order:

```text
sig1 = signature from member 1
sig2 = signature from member 2
sig3 = signature from member 3
```

This is why `main.py` builds a fixed member order before registration.

## Running the Coordinator

Start member 2 and member 3 first. Then run `main.py`:

```bash
python3 A2/main.py \
  --role coordinator \
  --key A1/marco/private_key.pem \
  --peer2 <member2_public_key_hex> \
  --peer3 <member3_public_key_hex> \
  --port 8090 \
  --discovery-timeout 300 \
  --debug-peers
```

`--discovery-timeout 300` allows up to 5 minutes for peer discovery before failing.

`--debug-peers` prints visible peer public keys while waiting, which helps diagnose firewall, NAT, VPN, or wrong-key problems.

## Expected Output

A successful run should look like:

```text
[registration] Group registered: <group_id>
[round 1] I am submitter
[round 1] challenge received
[round 1] signature from member 2
[round 1] signature from member 3
[round 1] ok: Round 1 recorded at ...
[round 2] triggering member 2 as submitter
[round 2] signing for submitter
[round 3] signing for submitter
```

The final server response for round 3 is sent to the round 3 submitter, so `main.py` may not print the final "all 3 rounds done" line even when the group completed successfully.
