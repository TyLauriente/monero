# Trezor Host Protocol v2 (THP) — Monero implementation

This directory implements the host side of the Trezor Host Protocol v2,
the end-to-end-encrypted wire protocol that the Trezor Safe 7 — and any
future Trezor devices that drop the legacy v1 protocol — speak
exclusively. The protocol is specified at:

  - <https://docs.trezor.io/trezor-firmware/common/thp/specification.md>
  - <https://github.com/trezor/trezor-firmware/blob/main/docs/common/thp/specification.md>

THP is built on the Noise Protocol Framework (`Noise_XX_25519_AESGCM_SHA256`)
plus a few THP-specific deviations (see "Spec deviations" below).

## Layout

| File | Purpose |
| ---- | ------- |
| `crc32.hpp` | CRC-32 (IEEE polynomial) used for transport-frame integrity, on top of `boost::crc`. |
| `framing.{hpp,cpp}` | Wire-level segmentation. `encode_frame` produces 64-byte USB chunks; `FrameAssembler` reassembles them and verifies the CRC. |
| `channel.{hpp,cpp}` | Channel allocation on the broadcast CID 0xFFFF — sends a `ChannelAllocationRequest` with an 8-byte nonce, parses the `ChannelAllocationResponse` with the assigned CID and the device-properties protobuf. |
| `noise.{hpp,cpp}` | Cryptographic primitives (X25519 / SHA-256 / HMAC-SHA-256 / THP HKDF / AES-256-GCM / Trezor-static-key masking) and the `NoiseXxInitiator` state machine that runs the host side of the handshake (HH0 → HH1 → HH2/HH3). |
| `protocol_v2.{hpp,cpp}` | `ProtocolV2 : public Protocol` — drop-in replacement for `ProtocolV1` that performs allocation + handshake on `session_begin` and AES-GCM-seals/opens application traffic on `write` / `read`. |

## Status

| Component | Status |
| --------- | ------ |
| CRC-32 + framing | Done. Round-trip and CRC-mismatch tests in `tests/unit_tests/device_trezor_thp.cpp`. |
| Channel allocation | Done. |
| Noise primitives (SHA-256, HMAC-SHA-256, THP HKDF, X25519, AES-GCM, masked-static-key) | Done. Each primitive has a deterministic test vector. |
| `NoiseXxInitiator` state machine | Done. End-to-end handshake validated against a simulated Trezor in `tests/unit_tests/device_trezor_thp.cpp:thp_handshake.full_handshake_self_test`. |
| `TransportCipher` | Done. Seal/open round-trip tested. |
| `ProtocolV2` (alloc + handshake + transport) | Wired up; depends on the rest of this directory. Not yet exercised against a real Safe 7. |
| Probe-based protocol selection (V1 vs THP) | Not implemented. Currently selected via the `TREZOR_FORCE_THP=1` environment variable — see `transport.cpp`. |
| Pairing FSM (CodeEntry / QR / NFC) | Not implemented. See "Pairing" below. |
| THP-specific protobuf messages (`messages-thp.proto`) | Not vendored yet. The handshake itself does not need them; pairing and credential flows do. |

## Verified vs. unverified

What is verified by the deterministic unit tests in
`tests/unit_tests/device_trezor_thp.cpp`:

  - Each cryptographic primitive against published RFC / NIST test vectors.
  - The Noise XX handshake completes between the host implementation and
    an in-process Trezor simulator that follows the spec's state machine
    verbatim. Both sides agree on the resulting transport keys and
    handshake hash, which pins:
      - the protocol-name + device-properties initial hash,
      - the IV layout (`0^96` for nonce 0, `0^95||1` for nonce 1, …),
      - mix-hash ordering across the four handshake messages,
      - the AAD used in each AES-GCM call,
      - the THP HKDF cascade,
      - and the masked-static-key construction.
    A bug present on both sides of this test would not be detected; only
    a bug that diverges from the spec on one side is caught.

What is **not** verified yet:

  - Anything against a real Trezor Safe 7. The implementation has not
    been exercised against hardware. End-to-end checkout (channel
    allocation through one application-layer round-trip such as
    `GetFeatures`) is required before this code can be shipped to users.
  - The protocol-selection probe — there is no probe yet; THP is
    currently opt-in via `TREZOR_FORCE_THP=1`.

## Spec deviations from "stock" Noise XX

The THP spec departs from the Noise Protocol Framework's symmetric-state
abstraction in three places that the implementation must honour
literally:

  1. **Initial chaining key**:
     `(ck, k) = HKDF(protocol_name, X25519(host_eph_priv, trezor_eph_pub))`.
     The first argument to HKDF is the literal 32-byte
     `Noise_XX_25519_AESGCM_SHA256\0\0\0\0` string, not
     `SHA-256(protocol_name)`.
  2. **Initial hash**:
     `h = SHA-256(protocol_name || device_properties)`. The device
     properties advertised in `ChannelAllocationResponse` are mixed in
     before the ephemeral keys.
  3. **Trezor static key masking**: the value the host receives is
     `X25519(SHA-256(static_pub || eph_pub), static_pub)`. The host uses
     this masked value directly as the peer static key for the second DH
     and the HKDF that follows. Pairing is a separate phase that
     identifies a previously-paired device by recomputing the masked
     value with the stored real static key and comparing.

The IV layout matches the spec's notation: `0^96` is the 12-byte all-zero
IV, `0^95 || 1` is `00 ... 00 01` — a 4-byte zero prefix followed by the
64-bit Noise nonce in **big-endian** byte order. Nonce 0 and nonce 1
look identical to standard Noise; nonce ≥ 2 differs (Noise specifies
little-endian).

## Pairing

The handshake produces a confidential channel but, on its own, only
gives weak (TOFU) authentication of the device. Per the spec, mutual
authentication requires a one-time pairing step in which the user
confirms a code displayed on the Trezor matches one displayed by the
host, after which Trezor issues a long-lived credential the host can
present on subsequent connections.

Pairing UX (rendering the code, accepting user input) lives in the
GUI; the protocol layer only needs to drive the FSM. The state machine
is documented in specification.md sections "Pairing phase" / "Credential
phase". Wiring it up should follow the same pattern as the existing
Trezor passphrase callback in `device_trezor_base.cpp` — a callback
the device-glue layer registers with `ProtocolV2` and the GUI hooks
into.

## Probe-based protocol selection

Today, `transport.cpp` picks `ProtocolV1` by default and switches to
`ProtocolV2` only when `TREZOR_FORCE_THP=1` is set in the environment.
This avoids the risk of locking up an attached Model T by sending it a
THP frame it cannot parse.

The intended design for auto-detection is:

  1. On `open()`, send a `ChannelAllocationRequest` on the broadcast
     CID (a single 64-byte USB packet — the `framing.cpp` code already
     produces it).
  2. Read up to 64 bytes back. Examine the first byte:
     - `0x41` = `CTRL_CHANNEL_ALLOC_RESPONSE` — Safe 7. Continue with
       the response and reuse the freshly-allocated channel.
     - `0x3F` (the legacy v1 `?` magic) or no response — Model T or
       earlier. Discard the dangling allocation and use `ProtocolV1`.
  3. Cache the decision per device-path so a single probe per
     attach is enough.

This design has not been validated against a real Model T, so it is
documented here rather than implemented. The env-var fallback remains
the supported entry point until somebody with both devices on hand can
verify it.

## References

  - THP specification: <https://docs.trezor.io/trezor-firmware/common/thp/>
  - Noise Protocol Framework: <https://noiseprotocol.org/noise.html>
  - RFC 7748 (X25519): <https://datatracker.ietf.org/doc/html/rfc7748>
  - RFC 4231 (HMAC-SHA-256 test vectors): <https://datatracker.ietf.org/doc/html/rfc4231>
  - RFC 5869 (HKDF, for the construction principle that THP's HKDF is
    a specialisation of): <https://datatracker.ietf.org/doc/html/rfc5869>
  - NIST SP 800-38D (AES-GCM): <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
  - Upstream tracking issue (Monero core): <https://github.com/monero-project/monero/issues/10368>
  - Upstream tracking issue (Monero GUI): <https://github.com/monero-project/monero-gui/issues/4517>
