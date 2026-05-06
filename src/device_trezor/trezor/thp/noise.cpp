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

#include "noise.hpp"
#include "../exceptions.hpp"

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace hw { namespace trezor { namespace thp {

  // Per specification.md §"Common definitions": the protocol name is the
  // ASCII string `Noise_XX_25519_AESGCM_SHA256` followed by four NUL bytes
  // (32 bytes total). It is used both as the initial chaining-key argument
  // to HKDF and as the prefix of h.
  static const uint8_t PROTOCOL_NAME[] = {
    'N','o','i','s','e','_','X','X','_','2','5','5','1','9',
    '_','A','E','S','G','C','M','_','S','H','A','2','5','6',
    0x00, 0x00, 0x00, 0x00,
  };
  static_assert(sizeof(PROTOCOL_NAME) == 32,
                "THP protocol name must be 32 bytes (28 ASCII + 4 zero)");

  namespace crypto {

    void sha256(const uint8_t *data, size_t len, NoiseHash &out)
    {
      crypto_hash_sha256(out.data(), data, len);
    }

    void hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     NoiseHash &out)
    {
      // libsodium's single-shot crypto_auth_hmacsha256() requires the key to
      // be exactly KEYBYTES (32). For other key lengths we use the streaming
      // API, which performs the HMAC key-schedule (hash-or-pad-to-blocksize)
      // per RFC 2104.
      crypto_auth_hmacsha256_state st;
      crypto_auth_hmacsha256_init(&st, key, key_len);
      crypto_auth_hmacsha256_update(&st, data, data_len);
      crypto_auth_hmacsha256_final(&st, out.data());
    }

    void thp_hkdf(const uint8_t *ck, size_t ck_len,
                  const uint8_t *ikm, size_t ikm_len,
                  NoiseKey &out1, NoiseKey &out2)
    {
      // Per specification.md §"Common definitions":
      //   temp_key = HMAC-SHA-256(ck, input)
      //   output_1 = HMAC-SHA-256(temp_key, 0x01)
      //   output_2 = HMAC-SHA-256(temp_key, output_1 || 0x02)
      NoiseHash temp_key{};
      hmac_sha256(ck, ck_len, ikm, ikm_len, temp_key);

      const uint8_t one = 0x01;
      NoiseHash o1{};
      hmac_sha256(temp_key.data(), temp_key.size(), &one, 1, o1);
      std::memcpy(out1.data(), o1.data(), out1.size());

      std::array<uint8_t, NOISE_HASHLEN + 1> o1_with_two{};
      std::memcpy(o1_with_two.data(), o1.data(), NOISE_HASHLEN);
      o1_with_two[NOISE_HASHLEN] = 0x02;
      NoiseHash o2{};
      hmac_sha256(temp_key.data(), temp_key.size(),
                  o1_with_two.data(), o1_with_two.size(), o2);
      std::memcpy(out2.data(), o2.data(), out2.size());

      sodium_memzero(temp_key.data(), temp_key.size());
      sodium_memzero(o1.data(),       o1.size());
      sodium_memzero(o1_with_two.data(), o1_with_two.size());
      sodium_memzero(o2.data(),       o2.size());
    }

    void x25519(const NoisePrivKey &priv, const NoisePubKey &peer,
                NoisePubKey &out)
    {
      // crypto_scalarmult returns -1 if the result is the all-zero point.
      // Per RFC 7748 §6.1 that indicates a degenerate peer key and MUST be
      // treated as an error.
      if (crypto_scalarmult(out.data(), priv.data(), peer.data()) != 0) {
        throw exc::SecurityException("THP: X25519 produced all-zero output (low-order peer key)");
      }
    }

    void x25519_base(const NoisePrivKey &priv, NoisePubKey &out)
    {
      crypto_scalarmult_base(out.data(), priv.data());
    }

    void x25519_keypair(NoisePubKey &pub, NoisePrivKey &priv)
    {
      randombytes_buf(priv.data(), priv.size());
      // Clamp per RFC 7748 §5.
      priv[0]  &= 248;
      priv[31] &= 127;
      priv[31] |= 64;
      crypto_scalarmult_base(pub.data(), priv.data());
    }

    void iv_for_nonce(uint64_t counter, NoiseIv &out)
    {
      // 12-byte IV: 4 zero bytes followed by the 64-bit counter big-endian.
      // Matches the spec notation: counter=0 -> 0^96, counter=1 -> 0^95||1.
      std::memset(out.data(), 0, out.size());
      out[4]  = uint8_t(counter >> 56);
      out[5]  = uint8_t(counter >> 48);
      out[6]  = uint8_t(counter >> 40);
      out[7]  = uint8_t(counter >> 32);
      out[8]  = uint8_t(counter >> 24);
      out[9]  = uint8_t(counter >> 16);
      out[10] = uint8_t(counter >>  8);
      out[11] = uint8_t(counter);
    }

    namespace {
      // RAII wrapper around EVP_CIPHER_CTX (avoids leaks on throw).
      struct EvpCtx {
        EVP_CIPHER_CTX *p = EVP_CIPHER_CTX_new();
        ~EvpCtx() { if (p) EVP_CIPHER_CTX_free(p); }
        EvpCtx() = default;
        EvpCtx(const EvpCtx &) = delete;
        EvpCtx &operator=(const EvpCtx &) = delete;
      };
    }

    bool aes256gcm_encrypt(const NoiseKey &key, const NoiseIv &iv,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           std::vector<uint8_t> &ciphertext)
    {
      EvpCtx ctx;
      if (!ctx.p) return false;
      if (EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;
      if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
        return false;
      if (EVP_EncryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv.data()) != 1)
        return false;

      ciphertext.resize(plaintext_len + NOISE_TAGLEN);
      int dummy_outl = 0;
      if (aad_len) {
        // AAD pass: EVP fills dummy_outl with the AAD length, but no
        // ciphertext bytes are written here.
        if (EVP_EncryptUpdate(ctx.p, nullptr, &dummy_outl, aad, (int)aad_len) != 1)
          return false;
      }
      int ct_outl = 0;
      if (plaintext_len) {
        if (EVP_EncryptUpdate(ctx.p, ciphertext.data(), &ct_outl,
                              plaintext, (int)plaintext_len) != 1)
          return false;
      }
      int ct_finall = 0;
      if (EVP_EncryptFinal_ex(ctx.p, ciphertext.data() + ct_outl, &ct_finall) != 1)
        return false;
      // ct_outl + ct_finall MUST equal plaintext_len for AES-GCM (no padding).
      if (size_t(ct_outl + ct_finall) != plaintext_len)
        return false;
      if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, NOISE_TAGLEN,
                              ciphertext.data() + plaintext_len) != 1)
        return false;
      return true;
    }

    bool aes256gcm_decrypt(const NoiseKey &key, const NoiseIv &iv,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           std::vector<uint8_t> &plaintext)
    {
      if (ciphertext_len < NOISE_TAGLEN) return false;
      const size_t plain_len = ciphertext_len - NOISE_TAGLEN;

      EvpCtx ctx;
      if (!ctx.p) return false;
      if (EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;
      if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
        return false;
      if (EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv.data()) != 1)
        return false;

      plaintext.resize(plain_len);
      int dummy_outl = 0;
      if (aad_len) {
        if (EVP_DecryptUpdate(ctx.p, nullptr, &dummy_outl, aad, (int)aad_len) != 1)
          return false;
      }
      int pt_outl = 0;
      if (plain_len) {
        if (EVP_DecryptUpdate(ctx.p, plaintext.data(), &pt_outl,
                              ciphertext, (int)plain_len) != 1)
          return false;
      }
      // Set the expected tag, then EVP_DecryptFinal_ex performs the
      // verification.  EVP_CTRL_GCM_SET_TAG takes a non-const buffer
      // pointer; cast away constness (OpenSSL does not write to it).
      if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, NOISE_TAGLEN,
                              const_cast<uint8_t *>(ciphertext + plain_len)) != 1)
        return false;
      int pt_finall = 0;
      if (EVP_DecryptFinal_ex(ctx.p, plaintext.data() + pt_outl, &pt_finall) != 1) {
        sodium_memzero(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
      }
      if (size_t(pt_outl + pt_finall) != plain_len) {
        sodium_memzero(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
      }
      return true;
    }

    void trezor_mask_static(const NoisePubKey &trezor_static_pub,
                            const NoisePubKey &trezor_ephemeral_pub,
                            NoisePubKey &out_masked)
    {
      // mask = SHA-256(static_pub || ephemeral_pub)
      std::array<uint8_t, NOISE_DHLEN * 2> concat{};
      std::memcpy(concat.data(),               trezor_static_pub.data(),    NOISE_DHLEN);
      std::memcpy(concat.data() + NOISE_DHLEN, trezor_ephemeral_pub.data(), NOISE_DHLEN);
      NoiseHash mask{};
      sha256(concat.data(), concat.size(), mask);

      NoisePrivKey scalar{};
      std::memcpy(scalar.data(), mask.data(), NOISE_DHLEN);
      x25519(scalar, trezor_static_pub, out_masked);

      sodium_memzero(scalar.data(), scalar.size());
      sodium_memzero(mask.data(),   mask.size());
    }

  } // namespace crypto

  // ---------------------------------------------------------------------------
  // NoiseXxInitiator
  // ---------------------------------------------------------------------------

  NoiseXxInitiator::NoiseXxInitiator() = default;

  NoiseXxInitiator::~NoiseXxInitiator()
  {
    sodium_memzero(m_host_static.priv.data(),     m_host_static.priv.size());
    sodium_memzero(m_host_ephemeral_priv.data(),  m_host_ephemeral_priv.size());
    sodium_memzero(m_ck_or_zero.data(),           m_ck_or_zero.size());
    sodium_memzero(m_k_handshake.data(),          m_k_handshake.size());
    sodium_memzero(m_h.data(),                    m_h.size());
    sodium_memzero(m_keys.key_request.data(),     m_keys.key_request.size());
    sodium_memzero(m_keys.key_response.data(),    m_keys.key_response.size());
    sodium_memzero(m_keys.handshake_hash.data(),  m_keys.handshake_hash.size());
    if (!m_pairing_credential.empty())
      sodium_memzero(m_pairing_credential.data(), m_pairing_credential.size());
    for (auto &kd : m_known_devices) {
      sodium_memzero(kd.host_static.priv.data(),  kd.host_static.priv.size());
      if (!kd.pairing_credential.empty())
        sodium_memzero(kd.pairing_credential.data(), kd.pairing_credential.size());
    }
  }

  void NoiseXxInitiator::set_device_properties(const uint8_t *data, size_t len)
  {
    m_device_properties.assign(data, data + len);
    m_have_device_properties = true;
  }

  void NoiseXxInitiator::set_host_static_key(const HostStaticKey &host_static)
  {
    m_host_static = host_static;
    m_have_host_static = true;
  }

  void NoiseXxInitiator::set_known_devices(std::vector<KnownDevice> known)
  {
    m_known_devices = std::move(known);
  }

  void NoiseXxInitiator::mix_hash(const uint8_t *data, size_t len)
  {
    // h = SHA-256(h || data)
    std::vector<uint8_t> buf;
    buf.reserve(NOISE_HASHLEN + len);
    buf.insert(buf.end(), m_h.begin(), m_h.end());
    if (len) buf.insert(buf.end(), data, data + len);
    crypto::sha256(buf.data(), buf.size(), m_h);
  }

  std::vector<uint8_t> NoiseXxInitiator::build_init_request(bool try_to_unlock)
  {
    if (!m_have_host_static) {
      throw exc::ProtocolException("THP: build_init_request without host static key");
    }
    if (!m_have_device_properties) {
      throw exc::ProtocolException("THP: build_init_request without device properties");
    }

    crypto::x25519_keypair(m_host_ephemeral_pub, m_host_ephemeral_priv);
    m_have_ephemeral = true;
    m_try_to_unlock  = try_to_unlock;

    std::vector<uint8_t> body;
    body.reserve(NOISE_DHLEN + 1);
    body.insert(body.end(), m_host_ephemeral_pub.begin(), m_host_ephemeral_pub.end());
    body.push_back(try_to_unlock ? 0x01 : 0x00);
    return body;
  }

  void NoiseXxInitiator::consume_init_response(const uint8_t *body, size_t len)
  {
    if (!m_have_ephemeral) {
      throw exc::ProtocolException("THP: consume_init_response before build_init_request");
    }
    // Per specification.md HandshakeInitiationResponse layout: 32 + 48 + 16 = 96.
    constexpr size_t TREZOR_EPH_OFF       = 0;
    constexpr size_t ENC_STATIC_OFF       = NOISE_DHLEN;
    constexpr size_t ENC_STATIC_LEN       = NOISE_DHLEN + NOISE_TAGLEN; // 48
    constexpr size_t TAG_OFF              = ENC_STATIC_OFF + ENC_STATIC_LEN;
    constexpr size_t TAG_LEN              = NOISE_TAGLEN;
    constexpr size_t EXPECTED_LEN         = TAG_OFF + TAG_LEN;
    if (len != EXPECTED_LEN) {
      throw exc::ProtocolException("THP: HandshakeInitResponse wrong size");
    }

    // h = SHA-256(protocol_name || device_properties)
    std::vector<uint8_t> hash_in;
    hash_in.reserve(sizeof(PROTOCOL_NAME) + m_device_properties.size());
    hash_in.insert(hash_in.end(), PROTOCOL_NAME, PROTOCOL_NAME + sizeof(PROTOCOL_NAME));
    hash_in.insert(hash_in.end(), m_device_properties.begin(), m_device_properties.end());
    crypto::sha256(hash_in.data(), hash_in.size(), m_h);

    // h = SHA-256(h || host_eph_pub)
    mix_hash(m_host_ephemeral_pub.data(), m_host_ephemeral_pub.size());
    // h = SHA-256(h || try_to_unlock)
    {
      const uint8_t b = m_try_to_unlock ? 0x01 : 0x00;
      mix_hash(&b, 1);
    }

    std::memcpy(m_trezor_ephemeral_pub.data(), body + TREZOR_EPH_OFF, NOISE_DHLEN);
    // h = SHA-256(h || trezor_eph_pub)
    mix_hash(m_trezor_ephemeral_pub.data(), m_trezor_ephemeral_pub.size());

    // (ck, k) = HKDF(protocol_name, X25519(host_eph_priv, trezor_eph_pub))
    NoisePubKey ee{};
    crypto::x25519(m_host_ephemeral_priv, m_trezor_ephemeral_pub, ee);
    NoiseKey ck{}, k{};
    crypto::thp_hkdf(PROTOCOL_NAME, sizeof(PROTOCOL_NAME),
                     ee.data(), ee.size(), ck, k);
    sodium_memzero(ee.data(), ee.size());
    m_have_ck    = true;
    std::memcpy(m_ck_or_zero.data(), ck.data(), NOISE_KEYLEN);
    std::memcpy(m_k_handshake.data(), k.data(), NOISE_KEYLEN);

    // Decrypt encrypted_trezor_static_pubkey at IV=0^96, AAD=h.
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> dec_masked;
    if (!crypto::aes256gcm_decrypt(m_k_handshake, iv,
                                   m_h.data(), m_h.size(),
                                   body + ENC_STATIC_OFF, ENC_STATIC_LEN,
                                   dec_masked)) {
      throw exc::SecurityException("THP: HandshakeInitResponse: enc_static tag invalid");
    }
    if (dec_masked.size() != NOISE_DHLEN) {
      throw exc::ProtocolException("THP: HandshakeInitResponse: bad enc_static plaintext size");
    }
    std::memcpy(m_trezor_masked_static.data(), dec_masked.data(), NOISE_DHLEN);

    // h = SHA-256(h || enc_static)
    mix_hash(body + ENC_STATIC_OFF, ENC_STATIC_LEN);

    // (ck, k) = HKDF(ck, X25519(host_eph_priv, trezor_masked_static_pubkey))
    NoisePubKey se{};
    crypto::x25519(m_host_ephemeral_priv, m_trezor_masked_static, se);
    crypto::thp_hkdf(m_ck_or_zero.data(), m_ck_or_zero.size(),
                     se.data(), se.size(), ck, k);
    sodium_memzero(se.data(), se.size());
    std::memcpy(m_ck_or_zero.data(),  ck.data(), NOISE_KEYLEN);
    std::memcpy(m_k_handshake.data(), k.data(), NOISE_KEYLEN);

    // Decrypt the empty-payload tag at IV=0^96, AAD=h.
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> empty_payload;
    if (!crypto::aes256gcm_decrypt(m_k_handshake, iv,
                                   m_h.data(), m_h.size(),
                                   body + TAG_OFF, TAG_LEN,
                                   empty_payload)) {
      throw exc::SecurityException("THP: HandshakeInitResponse: trailing tag invalid");
    }
    if (!empty_payload.empty()) {
      throw exc::ProtocolException("THP: HandshakeInitResponse: trailing payload not empty");
    }
    // h = SHA-256(h || tag)
    mix_hash(body + TAG_OFF, TAG_LEN);

    // Identify whether this device is paired (HH1 step 11). The lookup is
    // O(known) per spec; for typical use (a few prior Trezors) this is fine.
    //
    // The masked static pubkey rotates each session (it's
    //   X25519(SHA-256(static_pub || trezor_eph_pub), static_pub)
    // where trezor_eph_pub is FRESHLY generated each connect), so we cannot
    // simply compare against a stored masked value. Per spec, we recompute
    // the mask using the *current* session's trezor_ephemeral_pub for each
    // stored unmasked static, and compare to the just-decrypted masked
    // value.
    m_paired = false;
    m_pairing_credential.clear();
    for (const auto &kd : m_known_devices) {
      NoisePubKey expected_masked{};
      crypto::trezor_mask_static(kd.trezor_static_pubkey,
                                 m_trezor_ephemeral_pub,
                                 expected_masked);
      if (sodium_memcmp(expected_masked.data(),
                        m_trezor_masked_static.data(),
                        NOISE_DHLEN) == 0)
      {
        m_paired             = true;
        m_host_static        = kd.host_static;
        m_have_host_static   = true;
        m_pairing_credential = kd.pairing_credential;
        break;
      }
    }
    m_consumed_init_response = true;
  }

  std::vector<uint8_t> NoiseXxInitiator::build_completion_request()
  {
    if (!m_consumed_init_response) {
      throw exc::ProtocolException("THP: build_completion_request before init response");
    }
    if (!m_have_host_static) {
      throw exc::ProtocolException("THP: build_completion_request without host static key");
    }

    // encrypt host_static_pubkey at IV=0^95||1, AAD=h.
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(1, iv);
    std::vector<uint8_t> enc_host_static;
    if (!crypto::aes256gcm_encrypt(m_k_handshake, iv,
                                   m_h.data(), m_h.size(),
                                   m_host_static.pub.data(), m_host_static.pub.size(),
                                   enc_host_static)) {
      throw exc::ProtocolException("THP: AES-GCM encrypt failed (host_static)");
    }
    // h = SHA-256(h || enc_host_static)
    mix_hash(enc_host_static.data(), enc_host_static.size());

    // (ck, k) = HKDF(ck, X25519(host_static_priv, trezor_eph_pub))
    NoisePubKey ss{};
    crypto::x25519(m_host_static.priv, m_trezor_ephemeral_pub, ss);
    NoiseKey ck{}, k{};
    crypto::thp_hkdf(m_ck_or_zero.data(), m_ck_or_zero.size(),
                     ss.data(), ss.size(), ck, k);
    sodium_memzero(ss.data(), ss.size());
    std::memcpy(m_ck_or_zero.data(),  ck.data(), NOISE_KEYLEN);
    std::memcpy(m_k_handshake.data(), k.data(), NOISE_KEYLEN);

    // Encrypt the protobuf-encoded ThpHandshakeCompletionReqNoisePayload.
    // For the unpaired flow, host_pairing_credential is omitted, which
    // serialises to zero bytes. For the paired flow, the field is the
    // opaque credential bytes prefixed with the standard protobuf
    // wire-tag for field=1, type=length-delimited, plus a varint length.
    // We synthesise the protobuf manually here to avoid adding a runtime
    // dependency on a generated message type at this layer.
    std::vector<uint8_t> payload_binary;
    if (m_paired && !m_pairing_credential.empty()) {
      payload_binary.push_back(0x0A); // field 1, wire type 2 (length-delimited)
      size_t n = m_pairing_credential.size();
      while (n >= 0x80) {
        payload_binary.push_back(uint8_t((n & 0x7F) | 0x80));
        n >>= 7;
      }
      payload_binary.push_back(uint8_t(n));
      payload_binary.insert(payload_binary.end(),
                            m_pairing_credential.begin(),
                            m_pairing_credential.end());
    }

    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> enc_payload;
    if (!crypto::aes256gcm_encrypt(m_k_handshake, iv,
                                   m_h.data(), m_h.size(),
                                   payload_binary.data(), payload_binary.size(),
                                   enc_payload)) {
      throw exc::ProtocolException("THP: AES-GCM encrypt failed (completion payload)");
    }
    // h = SHA-256(h || enc_payload)
    mix_hash(enc_payload.data(), enc_payload.size());

    std::vector<uint8_t> body;
    body.reserve(enc_host_static.size() + enc_payload.size());
    body.insert(body.end(), enc_host_static.begin(), enc_host_static.end());
    body.insert(body.end(), enc_payload.begin(),     enc_payload.end());
    return body;
  }

  void NoiseXxInitiator::consume_completion_response(const uint8_t *body,
                                                     size_t len)
  {
    if (!m_consumed_init_response) {
      throw exc::ProtocolException("THP: consume_completion_response before init response");
    }
    // (key_request, key_response) = HKDF(ck, empty_string)
    NoiseKey key_request{}, key_response{};
    crypto::thp_hkdf(m_ck_or_zero.data(), m_ck_or_zero.size(),
                     nullptr, 0, key_request, key_response);

    // trezor_state = AES-GCM-DECRYPT(key_response, IV=0^96, ad=empty, body)
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(0, iv);
    std::vector<uint8_t> trezor_state;
    if (!crypto::aes256gcm_decrypt(key_response, iv,
                                   nullptr, 0,
                                   body, len,
                                   trezor_state)) {
      throw exc::SecurityException("THP: HandshakeCompletionResponse: tag invalid");
    }
    if (trezor_state.size() != 1) {
      throw exc::ProtocolException("THP: HandshakeCompletionResponse: bad state plaintext size");
    }
    m_trezor_state = trezor_state[0];

    m_keys.key_request    = key_request;
    m_keys.key_response   = key_response;
    m_keys.handshake_hash = m_h;
    m_complete            = true;
  }

  const HandshakeKeys &NoiseXxInitiator::keys() const
  {
    if (!m_complete) {
      throw exc::ProtocolException("THP: keys() called before handshake completion");
    }
    return m_keys;
  }

  // ---------------------------------------------------------------------------
  // TransportCipher
  // ---------------------------------------------------------------------------

  TransportCipher::TransportCipher(const NoiseKey &key, uint64_t initial_nonce)
    : m_key(key), m_counter(initial_nonce) {}

  TransportCipher::~TransportCipher()
  {
    sodium_memzero(m_key.data(), m_key.size());
  }

  void TransportCipher::seal(const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             std::vector<uint8_t> &out)
  {
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(m_counter, iv);
    if (!crypto::aes256gcm_encrypt(m_key, iv, aad, aad_len,
                                   plaintext, plaintext_len, out)) {
      throw exc::ProtocolException("THP: AES-GCM seal failed");
    }
    // Each direction has its own counter (key_request / key_response). We
    // own one counter per cipherstate; advance by one after each operation.
    ++m_counter;
  }

  bool TransportCipher::open(const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             std::vector<uint8_t> &out)
  {
    crypto::NoiseIv iv{};
    crypto::iv_for_nonce(m_counter, iv);
    if (!crypto::aes256gcm_decrypt(m_key, iv, aad, aad_len,
                                   ciphertext, ciphertext_len, out)) {
      return false;
    }
    ++m_counter;
    return true;
  }

}}}
