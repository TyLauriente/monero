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

#include "pairing.hpp"
#include "../exceptions.hpp"

#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <openssl/bn.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace hw { namespace trezor { namespace thp {

  // ---------------------------------------------------------------------------
  // Elligator2 for Curve25519 (per RFC 9380 §G.2.1, IRTF CPACE Montgomery
  // suite). Implementation uses OpenSSL BN for field arithmetic mod
  // p = 2^255 - 19. Constant-time properties of the BN routines are
  // enabled via BN_FLG_CONSTTIME.
  // ---------------------------------------------------------------------------
  namespace {

    // RAII wrappers for OpenSSL BN.
    struct Bn {
      BIGNUM *p;
      Bn() : p(BN_new()) { BN_set_flags(p, BN_FLG_CONSTTIME); }
      ~Bn() { if (p) BN_clear_free(p); }
      Bn(const Bn &) = delete;
      Bn &operator=(const Bn &) = delete;
    };
    struct BnCtx {
      BN_CTX *p = BN_CTX_new();
      BnCtx() = default;
      ~BnCtx() { if (p) BN_CTX_free(p); }
      BnCtx(const BnCtx &) = delete;
      BnCtx &operator=(const BnCtx &) = delete;
    };

    // Convert little-endian 32-byte buffer to a BIGNUM.
    void le_to_bn(const uint8_t in[32], BIGNUM *out)
    {
      uint8_t be[32];
      for (int i = 0; i < 32; ++i) be[i] = in[31 - i];
      BN_bin2bn(be, 32, out);
      BN_set_flags(out, BN_FLG_CONSTTIME);
    }

    // Convert a BIGNUM (assumed reduced mod p) to a 32-byte little-endian buffer.
    void bn_to_le(const BIGNUM *in, uint8_t out[32])
    {
      uint8_t be[32] = {0};
      // BN_bn2binpad emits big-endian, zero-padded on the left.
      BN_bn2binpad(in, be, 32);
      for (int i = 0; i < 32; ++i) out[i] = be[31 - i];
    }

    // Initialise `out` with the prime p = 2^255 - 19.
    void init_p25519(BIGNUM *out)
    {
      // 2^255 - 19 (little-endian-byte-string form):
      // ed ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 7f
      static const uint8_t p_be[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
      };
      BN_bin2bn(p_be, 32, out);
      BN_set_flags(out, BN_FLG_CONSTTIME);
    }

    // a is a quadratic residue mod p iff a^((p-1)/2) == 1 (mod p),
    // assuming a != 0.  We compute Euler's criterion in constant time.
    bool is_square_mod_p(const BIGNUM *a, const BIGNUM *p_, BN_CTX *ctx)
    {
      // exponent = (p-1)/2
      Bn exp; BN_copy(exp.p, p_); BN_sub_word(exp.p, 1);
      BN_rshift1(exp.p, exp.p);
      Bn r;
      BN_mod_exp(r.p, a, exp.p, p_, ctx);
      // r is 0 if a == 0 mod p, 1 if QR, p-1 if non-QR.
      // Treat 0 as "square" (gx1 == 0 means the curve point is well-defined).
      if (BN_is_zero(r.p)) return true;
      return BN_is_one(r.p);
    }

  } // anon

  void elligator2_curve25519(const uint8_t r_bytes[32], uint8_t out_u[32])
  {
    BnCtx ctx;
    Bn p, J, two, one;
    init_p25519(p.p);
    BN_set_word(J.p, 486662);
    BN_set_word(two.p, 2);
    BN_set_word(one.p, 1);

    // Per RFC 7748 §5 / RFC 9380 §G.2.1, decode_coordinate clears the high
    // bit (bit 255) before converting the 32 little-endian bytes to a field
    // element. The reference Python trezorlib does this in
    // curve25519.decode_coordinate (`array[-1] &= 0x7F`); without the mask
    // we get a different `u` than the device whenever SHA-512's truncated
    // high bit is set (~50% of pairings), and CPace tags mismatch.
    uint8_t masked[32];
    std::memcpy(masked, r_bytes, 32);
    masked[31] &= 0x7F;

    Bn u; le_to_bn(masked, u.p);
    BN_mod(u.p, u.p, p.p, ctx.p);
    sodium_memzero(masked, sizeof(masked));

    // d = 1 + Z * u^2 (Z = 2)
    Bn u2;     BN_mod_sqr(u2.p, u.p, p.p, ctx.p);
    Bn zu2;    BN_mod_mul(zu2.p, two.p, u2.p, p.p, ctx.p);
    Bn d;      BN_mod_add(d.p, one.p, zu2.p, p.p, ctx.p);

    // x1 = -J / d if d != 0, else x1 = -J  (per CMOV in RFC 9380 §G.2.1)
    Bn d_is_zero;
    Bn x1;
    if (BN_is_zero(d.p)) {
      BN_sub(x1.p, p.p, J.p);  // -J mod p
    } else {
      Bn d_inv;
      BN_mod_inverse(d_inv.p, d.p, p.p, ctx.p);
      Bn neg_J; BN_sub(neg_J.p, p.p, J.p);
      BN_mod_mul(x1.p, neg_J.p, d_inv.p, p.p, ctx.p);
    }

    // gx1 = x1 * (x1^2 + J*x1 + 1)
    Bn x1sq; BN_mod_sqr(x1sq.p, x1.p, p.p, ctx.p);
    Bn Jx1;  BN_mod_mul(Jx1.p, J.p, x1.p, p.p, ctx.p);
    Bn inner; BN_mod_add(inner.p, x1sq.p, Jx1.p, p.p, ctx.p);
    BN_mod_add(inner.p, inner.p, one.p, p.p, ctx.p);
    Bn gx1; BN_mod_mul(gx1.p, x1.p, inner.p, p.p, ctx.p);

    // x2 = -x1 - J
    Bn neg_x1; BN_sub(neg_x1.p, p.p, x1.p);
    Bn x2;     BN_mod_sub(x2.p, neg_x1.p, J.p, p.p, ctx.p);

    Bn x;
    if (is_square_mod_p(gx1.p, p.p, ctx.p)) {
      BN_copy(x.p, x1.p);
    } else {
      BN_copy(x.p, x2.p);
    }

    bn_to_le(x.p, out_u);
  }

  // ---------------------------------------------------------------------------
  // CPace generator derivation (THP-specific).
  //
  // Per specification.md §"Notes":
  //   prefix  = 0x08 0x43 0x50 0x61 0x63 0x65 0x32 0x35 0x35 0x06     (10 bytes)
  //            ("CPace255" with a length prefix 0x08, suffix 0x06; this is
  //            the IRTF CPACE-X25519-SHA512 "DSI" tag in symmetric setting.)
  //   padding = 0x6f || 0x00 * 111 || 0x20                            (113 bytes)
  //   pregenerator = SHA-512(prefix || code || padding || handshake_hash || 0x00)[:32]
  //   generator    = ELLIGATOR2(pregenerator)
  // ---------------------------------------------------------------------------
  void cpace_derive_generator(const std::string &code,
                              const NoiseHash    &handshake_hash,
                              uint8_t out_generator[32])
  {
    static const uint8_t PREFIX[10] = {
      0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x06,
    };
    static const size_t  PADDING_ZERO_BYTES = 111;

    // Build the SHA-512 input: prefix || code || padding || handshake_hash || 0x00
    std::vector<uint8_t> input;
    input.reserve(sizeof(PREFIX) + code.size() + 1 + PADDING_ZERO_BYTES + 1
                  + handshake_hash.size() + 1);
    input.insert(input.end(), PREFIX, PREFIX + sizeof(PREFIX));
    input.insert(input.end(), code.begin(), code.end());
    // padding: 0x6f, then 111 zero bytes, then 0x20
    input.push_back(0x6f);
    input.insert(input.end(), PADDING_ZERO_BYTES, 0x00);
    input.push_back(0x20);
    input.insert(input.end(), handshake_hash.begin(), handshake_hash.end());
    input.push_back(0x00);

    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, input.data(), input.size());

    uint8_t pregenerator[32];
    std::memcpy(pregenerator, hash, 32);
    elligator2_curve25519(pregenerator, out_generator);

    sodium_memzero(hash, sizeof(hash));
    sodium_memzero(pregenerator, sizeof(pregenerator));
    sodium_memzero(input.data(), input.size());
  }

  // ---------------------------------------------------------------------------
  // Helper: tiny protobuf encoder for the messages we need to build by hand.
  // ---------------------------------------------------------------------------
  namespace {

    void pb_write_varint(std::vector<uint8_t> &out, uint64_t v)
    {
      while (v >= 0x80) {
        out.push_back(uint8_t((v & 0x7F) | 0x80));
        v >>= 7;
      }
      out.push_back(uint8_t(v));
    }

    void pb_write_string_field(std::vector<uint8_t> &out, uint32_t field_number,
                               const std::string &s)
    {
      // wire type 2 (length-delimited)
      pb_write_varint(out, (uint64_t(field_number) << 3) | 2);
      pb_write_varint(out, s.size());
      out.insert(out.end(), s.begin(), s.end());
    }

    void pb_write_bytes_field(std::vector<uint8_t> &out, uint32_t field_number,
                              const uint8_t *data, size_t len)
    {
      pb_write_varint(out, (uint64_t(field_number) << 3) | 2);
      pb_write_varint(out, len);
      out.insert(out.end(), data, data + len);
    }

    void pb_write_enum_field(std::vector<uint8_t> &out, uint32_t field_number,
                             uint32_t value)
    {
      // wire type 0 (varint)
      pb_write_varint(out, (uint64_t(field_number) << 3) | 0);
      pb_write_varint(out, value);
    }

  } // anon

  // ---------------------------------------------------------------------------
  // CodeEntryPairing FSM
  // ---------------------------------------------------------------------------

  CodeEntryPairing::CodeEntryPairing(const NoiseHash &handshake_hash)
    : m_h(handshake_hash) {}

  CodeEntryPairing::~CodeEntryPairing()
  {
    sodium_memzero(m_cpace_host_priv.data(), m_cpace_host_priv.size());
    sodium_memzero(m_shared_secret.data(),   m_shared_secret.size());
    if (!m_code.empty()) {
      sodium_memzero(&m_code[0], m_code.size());
      m_code.clear();
    }
  }

  std::vector<uint8_t> CodeEntryPairing::build_pairing_request(const std::string &host_name,
                                                               const std::string &app_name)
  {
    // ThpPairingRequest { string host_name = 1; string app_name = 2; }
    std::vector<uint8_t> out;
    pb_write_string_field(out, 1, host_name);
    pb_write_string_field(out, 2, app_name);
    return out;
  }

  std::vector<uint8_t> CodeEntryPairing::build_select_method_code_entry()
  {
    // ThpSelectMethod { ThpPairingMethod selected_pairing_method = 1; }
    // CodeEntry = 2
    std::vector<uint8_t> out;
    pb_write_enum_field(out, 1, /*CodeEntry*/2);
    return out;
  }

  std::vector<uint8_t> CodeEntryPairing::consume_commitment_build_challenge(
      const uint8_t *commitment, size_t len)
  {
    if (len != 32) {
      throw exc::ProtocolException("THP pairing: ThpCodeEntryCommitment.commitment must be 32 bytes");
    }
    std::memcpy(m_commitment.data(), commitment, 32);
    m_have_commitment = true;

    // Generate a random 16-byte challenge.
    randombytes_buf(m_challenge.data(), m_challenge.size());

    // ThpCodeEntryChallenge { bytes challenge = 1; }
    std::vector<uint8_t> out;
    pb_write_bytes_field(out, 1, m_challenge.data(), m_challenge.size());
    return out;
  }

  void CodeEntryPairing::consume_cpace_trezor(const uint8_t *cpace_trezor_pub, size_t len)
  {
    if (len != 32) {
      throw exc::ProtocolException("THP pairing: ThpCodeEntryCpaceTrezor.cpace_trezor_public_key must be 32 bytes");
    }
    std::memcpy(m_cpace_trezor_pub.data(), cpace_trezor_pub, 32);
    m_have_trezor_pub = true;
  }

  std::vector<uint8_t> CodeEntryPairing::build_host_tag(const std::string &code)
  {
    if (!m_have_trezor_pub) {
      throw exc::ProtocolException("THP pairing: build_host_tag before ThpCodeEntryCpaceTrezor");
    }
    if (code.empty()) {
      throw exc::ProtocolException("THP pairing: empty code");
    }
    if (code.size() > 6) {
      throw exc::ProtocolException("THP pairing: code longer than 6 digits");
    }
    for (char c : code) {
      if (c < '0' || c > '9') {
        throw exc::ProtocolException("THP pairing: code must be ASCII digits");
      }
    }
    // Per spec the device hashes f"{code:06}" — i.e. exactly 6 ASCII
    // digits, zero-padded on the left. The user may type "1234" but the
    // device computed against "001234"; without the pad CPace tags
    // mismatch and pairing silently fails for ~10% of generated codes.
    std::string padded = code;
    if (padded.size() < 6) {
      padded.insert(0, 6 - padded.size(), '0');
    }
    m_code = padded;

    // generator = ELLIGATOR2(SHA-512(prefix || code || padding || h || 0x00)[:32])
    uint8_t generator[32];
    cpace_derive_generator(padded, m_h, generator);

    // cpace_host_private_key = random 32 bytes
    randombytes_buf(m_cpace_host_priv.data(), m_cpace_host_priv.size());
    // CPace does not clamp the scalar (per IRTF draft) — but the X25519
    // function inside libsodium will internally apply curve25519 clamping
    // unconditionally. The CPace IRTF draft notes that this is acceptable
    // and matches the reference implementation's behaviour.

    // cpace_host_public_key = X25519(cpace_host_private_key, generator)
    NoisePrivKey priv{}; std::memcpy(priv.data(), m_cpace_host_priv.data(), 32);
    NoisePubKey  gen{};  std::memcpy(gen.data(),  generator,                32);
    NoisePubKey  pub{};
    crypto::x25519(priv, gen, pub);
    std::memcpy(m_cpace_host_pub.data(), pub.data(), 32);

    // shared_secret = X25519(cpace_host_private_key, cpace_trezor_public_key)
    NoisePubKey trezor_pub{};
    std::memcpy(trezor_pub.data(), m_cpace_trezor_pub.data(), 32);
    NoisePubKey shared{};
    crypto::x25519(priv, trezor_pub, shared);
    std::memcpy(m_shared_secret.data(), shared.data(), 32);

    sodium_memzero(generator,     sizeof(generator));
    sodium_memzero(priv.data(),   priv.size());
    sodium_memzero(shared.data(), shared.size());

    // tag = SHA-256(shared_secret)
    uint8_t tag[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(tag, m_shared_secret.data(), m_shared_secret.size());

    // ThpCodeEntryCpaceHostTag {
    //   bytes cpace_host_public_key = 1;
    //   bytes tag                   = 2;
    // }
    std::vector<uint8_t> out;
    pb_write_bytes_field(out, 1, m_cpace_host_pub.data(), m_cpace_host_pub.size());
    pb_write_bytes_field(out, 2, tag, sizeof(tag));
    sodium_memzero(tag, sizeof(tag));
    m_have_host_tag = true;
    return out;
  }

  bool CodeEntryPairing::consume_secret(const uint8_t *secret, size_t len)
  {
    if (!m_have_host_tag) {
      throw exc::ProtocolException("THP pairing: consume_secret before host tag sent");
    }
    if (len != 16) {
      throw exc::ProtocolException("THP pairing: ThpCodeEntrySecret.secret must be 16 bytes");
    }

    // (a) commitment == SHA-256(secret)
    uint8_t expected_commit[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(expected_commit, secret, len);
    if (sodium_memcmp(expected_commit, m_commitment.data(), 32) != 0) {
      return false;
    }

    // (b) code == SHA-256(ThpPairingMethod_CodeEntry || h || secret || challenge) % 1_000_000 (BE)
    // ThpPairingMethod_CodeEntry = 2 (per the proto enum; encode as a single byte
    // — the spec's hash input uses the raw enum number).
    std::vector<uint8_t> chash_in;
    chash_in.push_back(0x02);
    chash_in.insert(chash_in.end(), m_h.begin(), m_h.end());
    chash_in.insert(chash_in.end(), secret, secret + len);
    chash_in.insert(chash_in.end(), m_challenge.begin(), m_challenge.end());
    uint8_t code_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(code_hash, chash_in.data(), chash_in.size());
    sodium_memzero(chash_in.data(), chash_in.size());

    // Interpret the SHA-256 output as a big-endian integer mod 1_000_000.
    // 256 bits is far larger than 1_000_000; we reduce by long division.
    // Since we only care about the modulo, we can use OpenSSL BN.
    BnCtx ctx;
    Bn h_int; BN_bin2bn(code_hash, sizeof(code_hash), h_int.p);
    Bn modulus; BN_set_word(modulus.p, 1000000);
    Bn r; BN_mod(r.p, h_int.p, modulus.p, ctx.p);
    sodium_memzero(code_hash, sizeof(code_hash));
    BN_ULONG code_int = BN_get_word(r.p);

    // Parse user-entered code as decimal.
    // The spec format is: 6-digit code as ASCII digits.
    BN_ULONG entered = 0;
    for (char c : m_code) {
      if (c < '0' || c > '9') {
        // Tolerate anything non-digit by failing.
        return false;
      }
      entered = entered * 10 + (BN_ULONG)(c - '0');
    }
    if (entered != code_int) {
      return false;
    }

    m_paired = true;
    return true;
  }

}}}
