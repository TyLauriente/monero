// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Unit tests for the Trezor Host Protocol v2 (THP) data-transfer and
// secure-channel implementations.  The tests in this file are entirely
// deterministic; they do not require an attached Trezor or trezor-emu
// instance.  They cover:
//
//   - CRC-32 / framing round-trip (encode_frame -> FrameAssembler)
//   - CRC mismatch detection (tampered byte triggers an error)
//   - Reassembly across exactly-chunk-size boundaries
//   - Cryptographic primitives against published RFC / NIST vectors
//   - The Noise XX state machine, exercised by playing both the host and
//     the (simulated) Trezor sides of the handshake described in
//     specification.md.  This proves the handshake's symbolic correctness
//     end-to-end without requiring hardware.

#include "gtest/gtest.h"

#if defined(DEVICE_TREZOR_READY)

#include "device_trezor/trezor/thp/crc32.hpp"
#include "device_trezor/trezor/thp/framing.hpp"
#include "device_trezor/trezor/thp/noise.hpp"

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace hw::trezor::thp;

static std::vector<uint8_t> from_hex(const std::string &s) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    auto h = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return 0;
    };
    out.push_back(uint8_t((h(s[i]) << 4) | h(s[i+1])));
  }
  return out;
}

// ---------------------------------------------------------------------------
// CRC-32 (IEEE) wrapper. The classic verification vector is CRC32("123456789")
// = 0xCBF43926 for the IEEE polynomial / left-shift convention; boost::crc
// uses the reflected form, which yields the same final checksum.
// ---------------------------------------------------------------------------
TEST(thp_crc32, abc_vector)
{
  EXPECT_EQ(0xCBF43926u, crc32_ieee("123456789", 9));
}

// ---------------------------------------------------------------------------
// Framing: encode_frame followed by FrameAssembler reproduces the original
// payload bit-exactly, with the CRC stripped.
// ---------------------------------------------------------------------------
TEST(thp_framing, round_trip_short_payload)
{
  const uint8_t payload[] = "hello THP";
  const size_t  len       = sizeof(payload) - 1;

  auto wire = encode_frame(0x40 /*channel-alloc-req*/, 0xFFFF,
                           payload, len);
  ASSERT_EQ(USB_CHUNK_SIZE, wire.size());

  FrameAssembler asm_;
  ASSERT_TRUE(asm_.feed_chunk(wire.data(), USB_CHUNK_SIZE));
  Frame f = asm_.take();
  EXPECT_EQ(0x40, f.control_byte);
  EXPECT_EQ(0xFFFF, f.channel_id);
  ASSERT_EQ(len, f.payload.size());
  EXPECT_EQ(0, std::memcmp(f.payload.data(), payload, len));
}

TEST(thp_framing, round_trip_multi_chunk)
{
  // 200 bytes forces the assembler across at least three USB chunks.
  std::vector<uint8_t> payload(200);
  for (size_t i = 0; i < payload.size(); ++i) payload[i] = uint8_t(i ^ 0x5A);

  auto wire = encode_frame(0x04 /*encrypted-transport*/, 0x1234,
                           payload.data(), payload.size());
  ASSERT_EQ(0u, wire.size() % USB_CHUNK_SIZE);
  ASSERT_GE(wire.size(), USB_CHUNK_SIZE * 3);

  FrameAssembler asm_;
  for (size_t off = 0; off + USB_CHUNK_SIZE <= wire.size(); off += USB_CHUNK_SIZE) {
    bool done = asm_.feed_chunk(wire.data() + off, USB_CHUNK_SIZE);
    if (off + USB_CHUNK_SIZE == wire.size()) {
      EXPECT_TRUE(done);
    } else {
      EXPECT_FALSE(done);
    }
  }
  Frame f = asm_.take();
  EXPECT_EQ(0x04, f.control_byte);
  EXPECT_EQ(0x1234, f.channel_id);
  ASSERT_EQ(payload.size(), f.payload.size());
  EXPECT_EQ(0, std::memcmp(f.payload.data(), payload.data(), payload.size()));
}

TEST(thp_framing, round_trip_chunk_boundary)
{
  // A 59-byte payload exactly fills the first chunk's 64-byte capacity
  // (5-byte initiation header + 4-byte CRC + 55 payload), and the trailing
  // CRC bytes spill into a continuation packet — the off-by-one boundary
  // most likely to break the assembler.
  std::vector<uint8_t> payload(55, 0xAB);

  auto wire = encode_frame(0x04, 0x4321,
                           payload.data(), payload.size());
  ASSERT_EQ(0u, wire.size() % USB_CHUNK_SIZE);

  FrameAssembler asm_;
  bool done = false;
  for (size_t off = 0; off + USB_CHUNK_SIZE <= wire.size(); off += USB_CHUNK_SIZE) {
    done = asm_.feed_chunk(wire.data() + off, USB_CHUNK_SIZE);
  }
  ASSERT_TRUE(done);
  Frame f = asm_.take();
  EXPECT_EQ(payload.size(), f.payload.size());
}

TEST(thp_framing, crc_mismatch_throws)
{
  const uint8_t payload[] = "abcdefghij";
  auto wire = encode_frame(0x40, 0xFFFF, payload, sizeof(payload) - 1);

  // Flip a payload byte (offset 5 = first payload byte after the
  // initiation header).
  wire[5] ^= 0x01;

  FrameAssembler asm_;
  EXPECT_THROW(asm_.feed_chunk(wire.data(), USB_CHUNK_SIZE), std::exception);
}

// ---------------------------------------------------------------------------
// SHA-256 (NIST FIPS 180-4 example).
// ---------------------------------------------------------------------------
TEST(thp_crypto, sha256_abc)
{
  NoiseHash h{};
  crypto::sha256(reinterpret_cast<const uint8_t *>("abc"), 3, h);
  auto exp = from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ASSERT_EQ(32u, exp.size());
  EXPECT_EQ(0, std::memcmp(h.data(), exp.data(), exp.size()));
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256 (RFC 4231 test vectors 1 and 4).
// ---------------------------------------------------------------------------
TEST(thp_crypto, hmac_sha256_rfc4231_case1)
{
  auto key  = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  auto data = from_hex("4869205468657265"); // "Hi There"
  auto exp  = from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  NoiseHash mac{};
  crypto::hmac_sha256(key.data(), key.size(), data.data(), data.size(), mac);
  EXPECT_EQ(0, std::memcmp(mac.data(), exp.data(), exp.size()));
}

TEST(thp_crypto, hmac_sha256_rfc4231_case4)
{
  auto key  = from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
  auto data = from_hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                       "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
  auto exp  = from_hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
  NoiseHash mac{};
  crypto::hmac_sha256(key.data(), key.size(), data.data(), data.size(), mac);
  EXPECT_EQ(0, std::memcmp(mac.data(), exp.data(), exp.size()));
}

// ---------------------------------------------------------------------------
// X25519 — RFC 7748 §5.2 raw-scalar test vectors.
// ---------------------------------------------------------------------------
TEST(thp_crypto, x25519_rfc7748_section_5_2_iter1)
{
  auto priv_v = from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  auto peer_v = from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  auto exp_v  = from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  NoisePrivKey priv{}; std::memcpy(priv.data(), priv_v.data(), 32);
  NoisePubKey  peer{}; std::memcpy(peer.data(), peer_v.data(), 32);
  NoisePubKey  out{};
  crypto::x25519(priv, peer, out);
  EXPECT_EQ(0, std::memcmp(out.data(), exp_v.data(), exp_v.size()));
}

TEST(thp_crypto, x25519_rfc7748_section_5_2_iter2)
{
  auto priv_v = from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
  auto peer_v = from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
  auto exp_v  = from_hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
  NoisePrivKey priv{}; std::memcpy(priv.data(), priv_v.data(), 32);
  NoisePubKey  peer{}; std::memcpy(peer.data(), peer_v.data(), 32);
  NoisePubKey  out{};
  crypto::x25519(priv, peer, out);
  EXPECT_EQ(0, std::memcmp(out.data(), exp_v.data(), exp_v.size()));
}

TEST(thp_crypto, x25519_dh_symmetry)
{
  // Generate two random keypairs; verify the standard DH identity.
  NoisePubKey  a_pub{}, b_pub{};
  NoisePrivKey a_priv{}, b_priv{};
  crypto::x25519_keypair(a_pub, a_priv);
  crypto::x25519_keypair(b_pub, b_priv);
  NoisePubKey k1{}, k2{};
  crypto::x25519(a_priv, b_pub, k1);
  crypto::x25519(b_priv, a_pub, k2);
  EXPECT_EQ(0, std::memcmp(k1.data(), k2.data(), 32));
}

// ---------------------------------------------------------------------------
// AES-256-GCM (NIST CAVS gcmEncryptExtIV256.rsp count 0 and 2).
// ---------------------------------------------------------------------------
TEST(thp_crypto, aes256gcm_empty_message_zero_iv)
{
  NoiseKey         key{}; std::memset(key.data(), 0, key.size());
  crypto::NoiseIv  iv{};
  std::vector<uint8_t> ct;
  ASSERT_TRUE(crypto::aes256gcm_encrypt(key, iv, nullptr, 0, nullptr, 0, ct));
  ASSERT_EQ(NOISE_TAGLEN, ct.size());
  auto exp = from_hex("530f8afbc74536b9a963b4f1c4cb738b");
  EXPECT_EQ(0, std::memcmp(ct.data(), exp.data(), exp.size()));

  std::vector<uint8_t> pt;
  ASSERT_TRUE(crypto::aes256gcm_decrypt(key, iv, nullptr, 0,
                                        ct.data(), ct.size(), pt));
  EXPECT_TRUE(pt.empty());
}

TEST(thp_crypto, aes256gcm_16_bytes_zero_iv)
{
  NoiseKey         key{}; std::memset(key.data(), 0, key.size());
  crypto::NoiseIv  iv{};
  std::vector<uint8_t> pt(16, 0);
  std::vector<uint8_t> ct;
  ASSERT_TRUE(crypto::aes256gcm_encrypt(key, iv, nullptr, 0,
                                        pt.data(), pt.size(), ct));
  auto exp_ct  = from_hex("cea7403d4d606b6e074ec5d3baf39d18");
  auto exp_tag = from_hex("d0d1c8a799996bf0265b98b5d48ab919");
  ASSERT_EQ(32u, ct.size());
  EXPECT_EQ(0, std::memcmp(ct.data(),       exp_ct.data(),  16));
  EXPECT_EQ(0, std::memcmp(ct.data() + 16,  exp_tag.data(), 16));

  std::vector<uint8_t> rt;
  ASSERT_TRUE(crypto::aes256gcm_decrypt(key, iv, nullptr, 0,
                                        ct.data(), ct.size(), rt));
  EXPECT_EQ(rt, pt);
}

TEST(thp_crypto, aes256gcm_tamper_detected)
{
  NoiseKey         key{}; std::memset(key.data(), 0, key.size());
  crypto::NoiseIv  iv{};
  std::vector<uint8_t> pt(16, 0);
  std::vector<uint8_t> ct;
  ASSERT_TRUE(crypto::aes256gcm_encrypt(key, iv, nullptr, 0,
                                        pt.data(), pt.size(), ct));
  ct[0] ^= 0x01;
  std::vector<uint8_t> rt;
  EXPECT_FALSE(crypto::aes256gcm_decrypt(key, iv, nullptr, 0,
                                         ct.data(), ct.size(), rt));
}

// ---------------------------------------------------------------------------
// IV builder: nonce 0 yields 0^96, nonce 1 yields 0^95||1, larger counter
// values are encoded big-endian in the trailing 8 bytes.
// ---------------------------------------------------------------------------
TEST(thp_crypto, iv_for_nonce_layout)
{
  crypto::NoiseIv iv{};
  crypto::iv_for_nonce(0, iv);
  for (int i = 0; i < 12; ++i) EXPECT_EQ(0, iv[i]);

  crypto::iv_for_nonce(1, iv);
  for (int i = 0; i < 11; ++i) EXPECT_EQ(0, iv[i]);
  EXPECT_EQ(1, iv[11]);

  crypto::iv_for_nonce(0x0102030405060708ULL, iv);
  EXPECT_EQ(0x01, iv[4]);  EXPECT_EQ(0x02, iv[5]);
  EXPECT_EQ(0x03, iv[6]);  EXPECT_EQ(0x04, iv[7]);
  EXPECT_EQ(0x05, iv[8]);  EXPECT_EQ(0x06, iv[9]);
  EXPECT_EQ(0x07, iv[10]); EXPECT_EQ(0x08, iv[11]);
}

// ---------------------------------------------------------------------------
// THP HKDF self-consistency (regression check derived from the spec text).
// ---------------------------------------------------------------------------
TEST(thp_crypto, thp_hkdf_self_consistency)
{
  NoiseHash ck{};  std::memset(ck.data(),  'k', ck.size());
  NoiseHash ikm{}; std::memset(ikm.data(), 'v', ikm.size());

  NoiseHash temp{}, o1{}, o2{};
  crypto::hmac_sha256(ck.data(), ck.size(), ikm.data(), ikm.size(), temp);
  const uint8_t one = 0x01;
  crypto::hmac_sha256(temp.data(), temp.size(), &one, 1, o1);
  std::array<uint8_t, NOISE_HASHLEN + 1> o1p2{};
  std::memcpy(o1p2.data(), o1.data(), 32);
  o1p2[32] = 0x02;
  crypto::hmac_sha256(temp.data(), temp.size(),
                      o1p2.data(), o1p2.size(), o2);

  NoiseKey out1{}, out2{};
  crypto::thp_hkdf(ck.data(), ck.size(), ikm.data(), ikm.size(), out1, out2);
  EXPECT_EQ(0, std::memcmp(out1.data(), o1.data(), 32));
  EXPECT_EQ(0, std::memcmp(out2.data(), o2.data(), 32));
}

// ---------------------------------------------------------------------------
// trezor_mask_static is deterministic for fixed inputs and changes whenever
// the ephemeral public key changes (so paired-device lookups discriminate).
// ---------------------------------------------------------------------------
TEST(thp_crypto, trezor_mask_static_deterministic_and_eph_bound)
{
  NoisePubKey  static_pub{};
  NoisePrivKey static_priv{};
  crypto::x25519_keypair(static_pub, static_priv);

  NoisePubKey  eph_pub{};
  NoisePrivKey eph_priv{};
  crypto::x25519_keypair(eph_pub, eph_priv);

  NoisePubKey m1{}, m2{};
  crypto::trezor_mask_static(static_pub, eph_pub, m1);
  crypto::trezor_mask_static(static_pub, eph_pub, m2);
  EXPECT_EQ(0, std::memcmp(m1.data(), m2.data(), 32));

  NoisePubKey  eph_pub2{};
  NoisePrivKey eph_priv2{};
  crypto::x25519_keypair(eph_pub2, eph_priv2);
  NoisePubKey m_alt{};
  crypto::trezor_mask_static(static_pub, eph_pub2, m_alt);
  EXPECT_NE(0, std::memcmp(m1.data(), m_alt.data(), 32));
}

// ---------------------------------------------------------------------------
// Self-handshake: simulate the Trezor side of the handshake exactly per the
// state machine in specification.md, run a complete handshake against the
// real host implementation, and verify the two sides agree on the final
// transport keys and handshake hash.
//
// This is a SELF test (both sides are this code), so it would not catch a
// bug that is mirrored on both sides.  Its value is in pinning the
// algorithm: any deviation in IV layout, AAD, mix_hash ordering, masked
// key construction, or HKDF call shape between the two sides causes the
// AES-GCM tag to mismatch and the test to fail loudly.
// ---------------------------------------------------------------------------
namespace {

struct TrezorSide {
  NoisePubKey  static_pub{};
  NoisePrivKey static_priv{};
  NoisePubKey  ephemeral_pub{};
  NoisePrivKey ephemeral_priv{};
  std::vector<uint8_t> device_properties;

  NoiseHash h{};
  NoiseKey  ck{};
  NoiseKey  k{};

  HandshakeKeys keys{};
  std::vector<uint8_t> handshake_init_response;
  std::vector<uint8_t> handshake_completion_response;
  std::vector<uint8_t> decrypted_completion_payload;
  uint8_t              host_static_pub_received[NOISE_DHLEN] = {0};

  void mix_hash(const uint8_t *data, size_t len) {
    std::vector<uint8_t> buf;
    buf.reserve(NOISE_HASHLEN + len);
    buf.insert(buf.end(), h.begin(), h.end());
    if (len) buf.insert(buf.end(), data, data + len);
    crypto::sha256(buf.data(), buf.size(), h);
  }

  void handle_init_request(const std::vector<uint8_t> &req) {
    // req = host_eph_pub (32) || try_to_unlock (1)
    ASSERT_EQ(NOISE_DHLEN + 1u, req.size());

    crypto::x25519_keypair(ephemeral_pub, ephemeral_priv);

    // h = SHA-256(protocol_name || device_properties)
    static const uint8_t protocol_name[] = {
      'N','o','i','s','e','_','X','X','_','2','5','5','1','9',
      '_','A','E','S','G','C','M','_','S','H','A','2','5','6',
      0,0,0,0
    };
    std::vector<uint8_t> hash_in;
    hash_in.insert(hash_in.end(), protocol_name, protocol_name + sizeof(protocol_name));
    hash_in.insert(hash_in.end(), device_properties.begin(), device_properties.end());
    crypto::sha256(hash_in.data(), hash_in.size(), h);

    // h = SHA-256(h || host_eph_pub)
    mix_hash(req.data(), NOISE_DHLEN);
    // h = SHA-256(h || try_to_unlock)
    mix_hash(req.data() + NOISE_DHLEN, 1);
    // h = SHA-256(h || trezor_eph_pub)
    mix_hash(ephemeral_pub.data(), ephemeral_pub.size());

    // (ck, k) = HKDF(protocol_name, X25519(trezor_eph_priv, host_eph_pub))
    NoisePubKey host_eph_pub{};
    std::memcpy(host_eph_pub.data(), req.data(), NOISE_DHLEN);
    NoisePubKey ee{};
    crypto::x25519(ephemeral_priv, host_eph_pub, ee);
    crypto::thp_hkdf(protocol_name, sizeof(protocol_name),
                     ee.data(), ee.size(), ck, k);

    // mask = SHA-256(static_pub || trezor_eph_pub)
    NoisePubKey masked{};
    crypto::trezor_mask_static(static_pub, ephemeral_pub, masked);

    // enc_static = AES-GCM-Encrypt(k, IV=0^96, ad=h, masked)
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> enc_static;
    ASSERT_TRUE(crypto::aes256gcm_encrypt(k, iv, h.data(), h.size(),
                                          masked.data(), masked.size(),
                                          enc_static));
    // h = SHA-256(h || enc_static)
    mix_hash(enc_static.data(), enc_static.size());

    // (ck, k) = HKDF(ck, X25519(mask, X25519(static_priv, host_eph_pub)))
    NoisePubKey se{};
    crypto::x25519(static_priv, host_eph_pub, se);
    // The trezor side computes X25519(mask_scalar, ...). Equivalently, the
    // host computes X25519(host_eph_priv, masked). They produce the same DH
    // shared secret. Spec phrasing: ck, k = HKDF(ck, X25519(mask, se)).
    std::array<uint8_t, NOISE_DHLEN * 2> concat{};
    std::memcpy(concat.data(),               static_pub.data(),    NOISE_DHLEN);
    std::memcpy(concat.data() + NOISE_DHLEN, ephemeral_pub.data(), NOISE_DHLEN);
    NoiseHash mask_h{};
    crypto::sha256(concat.data(), concat.size(), mask_h);
    NoisePrivKey mask_scalar{};
    std::memcpy(mask_scalar.data(), mask_h.data(), NOISE_DHLEN);
    NoisePubKey ssm{};
    crypto::x25519(mask_scalar, se, ssm);
    crypto::thp_hkdf(ck.data(), ck.size(), ssm.data(), ssm.size(), ck, k);

    // tag = AES-GCM(k, IV=0^96, ad=h, plaintext=empty)
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> tag;
    ASSERT_TRUE(crypto::aes256gcm_encrypt(k, iv, h.data(), h.size(),
                                          nullptr, 0, tag));
    // h = SHA-256(h || tag)
    mix_hash(tag.data(), tag.size());

    handshake_init_response.clear();
    handshake_init_response.insert(handshake_init_response.end(),
                                   ephemeral_pub.begin(), ephemeral_pub.end());
    handshake_init_response.insert(handshake_init_response.end(),
                                   enc_static.begin(), enc_static.end());
    handshake_init_response.insert(handshake_init_response.end(),
                                   tag.begin(), tag.end());
  }

  void handle_completion_request(const std::vector<uint8_t> &req) {
    // req = enc_host_static (48) || enc_payload (var)
    ASSERT_GE(req.size(), 48u);
    const uint8_t *enc_host_static = req.data();
    const uint8_t *enc_payload     = req.data() + 48;
    const size_t   enc_payload_len = req.size() - 48;

    // host_static_pub = AES-GCM-Decrypt(k, IV=0^95||1, ad=h, enc_host_static)
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(1, iv);
    std::vector<uint8_t> host_static_pub;
    ASSERT_TRUE(crypto::aes256gcm_decrypt(k, iv, h.data(), h.size(),
                                          enc_host_static, 48, host_static_pub));
    ASSERT_EQ(NOISE_DHLEN, host_static_pub.size());
    std::memcpy(host_static_pub_received, host_static_pub.data(), NOISE_DHLEN);
    // h = SHA-256(h || enc_host_static)
    mix_hash(enc_host_static, 48);

    // (ck, k) = HKDF(ck, X25519(trezor_eph_priv, host_static_pub))
    NoisePubKey hsp{}; std::memcpy(hsp.data(), host_static_pub.data(), NOISE_DHLEN);
    NoisePubKey ss{};
    crypto::x25519(ephemeral_priv, hsp, ss);
    crypto::thp_hkdf(ck.data(), ck.size(), ss.data(), ss.size(), ck, k);

    // payload = AES-GCM-Decrypt(k, IV=0^96, ad=h, enc_payload)
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> payload;
    ASSERT_TRUE(crypto::aes256gcm_decrypt(k, iv, h.data(), h.size(),
                                          enc_payload, enc_payload_len, payload));
    decrypted_completion_payload = payload;
    // h = SHA-256(h || enc_payload)
    mix_hash(enc_payload, enc_payload_len);

    // (key_request, key_response) = HKDF(ck, empty)
    NoiseKey key_request{}, key_response{};
    crypto::thp_hkdf(ck.data(), ck.size(), nullptr, 0, key_request, key_response);

    // encrypted_state = AES-GCM-Encrypt(key_response, IV=0^96, ad=empty,
    //                                   plaintext=trezor_state byte)
    const uint8_t state_byte = 0x00; // STATE_UNPAIRED
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> encrypted_state;
    ASSERT_TRUE(crypto::aes256gcm_encrypt(key_response, iv,
                                          nullptr, 0,
                                          &state_byte, 1,
                                          encrypted_state));
    handshake_completion_response = encrypted_state;

    keys.key_request    = key_request;
    keys.key_response   = key_response;
    keys.handshake_hash = h;
  }
};

} // namespace

TEST(thp_handshake, full_handshake_self_test)
{
  TrezorSide trezor;
  // Generate the persistent Trezor static keypair.
  crypto::x25519_keypair(trezor.static_pub, trezor.static_priv);
  // Some non-empty device properties (real device sends a serialised
  // ThpDeviceProperties protobuf — for the purposes of this test the
  // bytes just need to match what the host hashes into h).
  trezor.device_properties = {0x0a, 0x04, 'T','2','B','1'};

  // Host side: fresh static keypair, no known devices.
  HostStaticKey host_static;
  crypto::x25519_keypair(host_static.pub, host_static.priv);

  NoiseXxInitiator host;
  host.set_device_properties(trezor.device_properties.data(),
                             trezor.device_properties.size());
  host.set_host_static_key(host_static);

  // Step 1: host -> trezor: HandshakeInitiationRequest
  auto init_req = host.build_init_request(/*try_to_unlock=*/false);
  trezor.handle_init_request(init_req);

  // Step 2: trezor -> host: HandshakeInitiationResponse
  host.consume_init_response(trezor.handshake_init_response.data(),
                             trezor.handshake_init_response.size());
  EXPECT_FALSE(host.is_known_device());

  // Step 3: host -> trezor: HandshakeCompletionRequest
  auto comp_req = host.build_completion_request();
  trezor.handle_completion_request(comp_req);

  // The unpaired flow sends an empty ThpHandshakeCompletionReqNoisePayload,
  // which serialises to zero protobuf bytes. The Trezor must therefore see
  // a zero-length decrypted payload.
  EXPECT_TRUE(trezor.decrypted_completion_payload.empty());

  // The Trezor must see exactly the host's static public key.
  EXPECT_EQ(0, std::memcmp(trezor.host_static_pub_received,
                           host_static.pub.data(), NOISE_DHLEN));

  // Step 4: trezor -> host: HandshakeCompletionResponse
  host.consume_completion_response(trezor.handshake_completion_response.data(),
                                   trezor.handshake_completion_response.size());
  ASSERT_TRUE(host.is_complete());
  EXPECT_EQ(0x00 /*STATE_UNPAIRED*/, host.trezor_state());

  // Both sides must have arrived at the same transport keys + handshake hash.
  const HandshakeKeys &hk = host.keys();
  EXPECT_EQ(0, std::memcmp(hk.key_request.data(),    trezor.keys.key_request.data(),    NOISE_KEYLEN));
  EXPECT_EQ(0, std::memcmp(hk.key_response.data(),   trezor.keys.key_response.data(),   NOISE_KEYLEN));
  EXPECT_EQ(0, std::memcmp(hk.handshake_hash.data(), trezor.keys.handshake_hash.data(), NOISE_HASHLEN));

  // The masked-static-pubkey decoded by the host must match what the
  // Trezor would have computed for itself (round-trip identity check).
  NoisePubKey expected_masked{};
  crypto::trezor_mask_static(trezor.static_pub, trezor.ephemeral_pub, expected_masked);
  EXPECT_EQ(0, std::memcmp(host.trezor_masked_static_pubkey().data(),
                           expected_masked.data(), NOISE_DHLEN));
}

// ---------------------------------------------------------------------------
// TransportCipher: round-trip seal / open with non-zero counters.
// ---------------------------------------------------------------------------
TEST(thp_transport_cipher, seal_open_round_trip)
{
  NoiseKey key{};
  for (size_t i = 0; i < key.size(); ++i) key[i] = uint8_t(i);

  TransportCipher tx(key, /*initial_nonce=*/0);
  TransportCipher rx(key, /*initial_nonce=*/0);

  for (int i = 0; i < 4; ++i) {
    std::vector<uint8_t> pt(64, uint8_t(i + 1));
    std::vector<uint8_t> ct;
    tx.seal(nullptr, 0, pt.data(), pt.size(), ct);
    EXPECT_EQ(pt.size() + NOISE_TAGLEN, ct.size());

    std::vector<uint8_t> back;
    ASSERT_TRUE(rx.open(nullptr, 0, ct.data(), ct.size(), back));
    EXPECT_EQ(pt, back);
  }
  EXPECT_EQ(4u, tx.nonce());
  EXPECT_EQ(4u, rx.nonce());
}

} // namespace

#endif // DEVICE_TREZOR_READY
