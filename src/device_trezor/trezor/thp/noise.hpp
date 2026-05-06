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

#ifndef MONERO_TREZOR_THP_NOISE_H
#define MONERO_TREZOR_THP_NOISE_H

#include <array>
#include <cstdint>
#include <vector>

namespace hw { namespace trezor { namespace thp {

  // Sizes of Noise primitives used by THP (Noise_XX_25519_AESGCM_SHA256).
  constexpr size_t NOISE_DHLEN   = 32; // X25519 public/private key
  constexpr size_t NOISE_HASHLEN = 32; // SHA-256 digest
  constexpr size_t NOISE_KEYLEN  = 32; // AES-256 key
  constexpr size_t NOISE_TAGLEN  = 16; // AES-GCM authentication tag

  using NoiseKey      = std::array<uint8_t, NOISE_KEYLEN>;
  using NoiseHash     = std::array<uint8_t, NOISE_HASHLEN>;
  using NoisePubKey   = std::array<uint8_t, NOISE_DHLEN>;
  using NoisePrivKey  = std::array<uint8_t, NOISE_DHLEN>;

  // Output of a successful handshake. The two AES-GCM keys are used by the
  // application-traffic phase. `handshake_hash` exposes the final value of
  // h, which is mixed into the pairing-code derivation.
  struct HandshakeKeys {
    NoiseKey  key_request;   // host -> device direction
    NoiseKey  key_response;  // device -> host direction
    NoiseHash handshake_hash;
  };

  // The host's static keypair, persisted across sessions per the spec.
  struct HostStaticKey {
    NoisePubKey  pub{};
    NoisePrivKey priv{};
  };

  // A previously-established pairing: the *unmasked* Trezor static pubkey
  // observed during an earlier handshake, the host static keypair that
  // was used with that device, and the opaque pairing credential issued
  // by Trezor in the credential phase.
  //
  // The masked form rotates per session (it depends on the device's fresh
  // ephemeral pubkey), so we must persist the unmasked pubkey and re-mask
  // each session before comparing — see specification.md HH1 step 11.
  struct KnownDevice {
    NoisePubKey   trezor_static_pubkey{};
    HostStaticKey host_static{};
    std::vector<uint8_t> pairing_credential; // opaque to the host
  };

  // ---------------------------------------------------------------------------
  // Low-level crypto primitives (host-implementation private, exposed for
  // unit tests).
  // ---------------------------------------------------------------------------
  namespace crypto {
    void sha256(const uint8_t *data, size_t len, NoiseHash &out);
    void hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     NoiseHash &out);

    // The HKDF used by THP, defined in the spec (specification.md, Common
    // definitions). Returns two 32-byte outputs derived from a chaining key
    // and an input keying material.
    void thp_hkdf(const uint8_t *ck, size_t ck_len,
                  const uint8_t *ikm, size_t ikm_len,
                  NoiseKey &out1, NoiseKey &out2);

    // X25519 scalar multiplication.
    void x25519(const NoisePrivKey &priv, const NoisePubKey &peer,
                NoisePubKey &out);
    void x25519_base(const NoisePrivKey &priv, NoisePubKey &out);

    // Generate a fresh X25519 keypair (clamps the private key per RFC 7748).
    void x25519_keypair(NoisePubKey &pub, NoisePrivKey &priv);

    // AES-256-GCM AEAD. The IV is 12 bytes per the THP spec; the spec
    // notates IVs as bit strings ("0^96", "0^95||1"). Helper iv_for_nonce
    // builds the 12-byte IV from a 64-bit counter (4 zero bytes followed by
    // the counter big-endian, matching the spec's notation: nonce=0 -> 0^96,
    // nonce=1 -> 0^95 || 1, etc.).
    using NoiseIv = std::array<uint8_t, 12>;
    void iv_for_nonce(uint64_t counter, NoiseIv &out);

    // Returns false on tag mismatch. plaintext must have room for ciphertext_len
    // - NOISE_TAGLEN bytes.
    bool aes256gcm_encrypt(const NoiseKey &key, const NoiseIv &iv,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           std::vector<uint8_t> &ciphertext);
    bool aes256gcm_decrypt(const NoiseKey &key, const NoiseIv &iv,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           std::vector<uint8_t> &plaintext);

    // Trezor's static key masking (specification.md §"Handshake phase"):
    //   masked = X25519(SHA-256(static_pub || ephemeral_pub), static_pub)
    // Pure function — exposed for tests and for the paired-device lookup
    // performed by the host (specification.md HH1 step 11).
    void trezor_mask_static(const NoisePubKey &trezor_static_pub,
                            const NoisePubKey &trezor_ephemeral_pub,
                            NoisePubKey &out_masked);
  }

  // ---------------------------------------------------------------------------
  // THP host-side handshake driver (Noise XX initiator role specialised for
  // the THP state machine — see specification.md §"Host's state machine").
  //
  // Usage:
  //   NoiseXxInitiator h;
  //   h.set_device_properties(ChannelAllocationResponse.device_properties);
  //   h.set_host_static_key(persisted_or_freshly_generated_keypair);
  //   h.set_known_devices(persisted_credentials);
  //
  //   auto req1 = h.build_init_request(try_to_unlock=false);
  //   // send req1, receive resp1
  //   h.consume_init_response(resp1.data(), resp1.size());
  //
  //   auto req2 = h.build_completion_request();
  //   // send req2, receive resp2
  //   h.consume_completion_response(resp2.data(), resp2.size());
  //
  //   const HandshakeKeys &keys = h.keys();
  //   bool paired = h.is_known_device();
  // ---------------------------------------------------------------------------
  class NoiseXxInitiator {
  public:
    NoiseXxInitiator();
    // Destructor wipes all derived key material and the host static
    // private key on scope exit (defense in depth against core dumps,
    // hibernation files, debugger access).
    ~NoiseXxInitiator();
    NoiseXxInitiator(const NoiseXxInitiator &) = delete;
    NoiseXxInitiator &operator=(const NoiseXxInitiator &) = delete;

    // Provide the device's properties as advertised in
    // ChannelAllocationResponse.device_properties. MUST be called before
    // build_init_request().
    void set_device_properties(const uint8_t *data, size_t len);

    // Provide the host's persistent static X25519 keypair. May be a
    // freshly-generated pair for first-time pairing, or loaded from disk.
    void set_host_static_key(const HostStaticKey &host_static);

    // Provide the list of previously-paired Trezors so the handshake can
    // detect a known device by its masked static pubkey (HH1 step 11). A
    // host with no prior pairings may pass an empty list.
    void set_known_devices(std::vector<KnownDevice> known);

    // Step 1 (HH0): generate ephemeral keypair, build the request body.
    std::vector<uint8_t> build_init_request(bool try_to_unlock);

    // Step 2 (HH1, partial): consume the init response, decrypt the
    // masked Trezor static pubkey and the empty-payload tag, mix in the
    // se DH. After this call, build_completion_request() is callable.
    void consume_init_response(const uint8_t *body, size_t len);

    // Step 3 (HH1, completion): build the completion request body.
    // Selects paired vs. unpaired flow based on the masked pubkey lookup
    // performed in consume_init_response.
    std::vector<uint8_t> build_completion_request();

    // Step 4 (HH2/HH3): consume the completion response and finalise the
    // handshake. After this call, keys() returns the post-handshake AES-GCM
    // keys and trezor_state() returns the byte the device reported.
    void consume_completion_response(const uint8_t *body, size_t len);

    // Whether the consumed init response matched a previously-paired device
    // (HH2 path). False indicates the unpaired flow (HH3) and that the
    // pairing phase must follow.
    bool is_known_device() const { return m_paired; }

    // The masked Trezor static pubkey decrypted from the init response.
    // Useful for logging / pairing UX.
    const NoisePubKey &trezor_masked_static_pubkey() const {
      return m_trezor_masked_static;
    }

    // The Trezor's reported state byte from HandshakeCompletionResponse:
    //   0x00 = STATE_UNPAIRED, 0x01 = STATE_PAIRED, 0x02 = STATE_PAIRED_AUTOCONNECT
    uint8_t trezor_state() const { return m_trezor_state; }

    bool is_complete() const { return m_complete; }
    const HandshakeKeys &keys() const;

    // The host static keypair actually in use after consume_init_response.
    // For the unpaired flow this is whatever set_host_static_key(...)
    // received. For the paired flow this is the keypair pulled from the
    // matching KnownDevice entry — the caller's outer copy is now stale
    // and should be re-synced from this accessor.
    const HostStaticKey &host_static_in_use() const { return m_host_static; }

  private:
    // Symmetric-state primitives, used per the spec to mix the running
    // handshake hash and chaining key.
    void mix_hash(const uint8_t *data, size_t len);

    bool                 m_have_device_properties = false;
    bool                 m_have_host_static       = false;
    bool                 m_have_ephemeral         = false;
    bool                 m_consumed_init_response = false;
    bool                 m_complete               = false;
    bool                 m_paired                 = false;
    uint8_t              m_trezor_state           = 0;

    std::vector<uint8_t> m_device_properties;
    HostStaticKey        m_host_static{};
    NoisePubKey          m_host_ephemeral_pub{};
    NoisePrivKey         m_host_ephemeral_priv{};
    NoisePubKey          m_trezor_ephemeral_pub{};
    NoisePubKey          m_trezor_masked_static{};
    bool                 m_try_to_unlock          = false;

    std::vector<KnownDevice>  m_known_devices;
    // When m_paired is true, this points at the entry in m_known_devices
    // whose masked pubkey matched. Otherwise empty.
    std::vector<uint8_t>      m_pairing_credential;

    // Symmetric state (h, ck, k) per the spec.
    NoiseHash m_h{};
    NoiseKey  m_ck_or_zero{};   // re-used as ck after the first HKDF
    bool      m_have_ck         = false;
    NoiseKey  m_k_handshake{};  // current handshake AES-GCM key

    HandshakeKeys m_keys{};
  };

  // Application-traffic AES-GCM cipherstate. Wraps a key and a 64-bit
  // counter; produces a 12-byte IV per the spec (`0^96` for nonce 0,
  // `0^95||1` for nonce 1, etc — i.e. 4 zero bytes followed by the
  // counter big-endian).
  class TransportCipher {
  public:
    explicit TransportCipher(const NoiseKey &key, uint64_t initial_nonce = 0);
    // Wipe the AES-GCM key on scope exit.
    ~TransportCipher();
    TransportCipher(const TransportCipher &) = delete;
    TransportCipher &operator=(const TransportCipher &) = delete;

    void seal(const uint8_t *aad, size_t aad_len,
              const uint8_t *plaintext, size_t plaintext_len,
              std::vector<uint8_t> &out);

    bool open(const uint8_t *aad, size_t aad_len,
              const uint8_t *ciphertext, size_t ciphertext_len,
              std::vector<uint8_t> &out);

    uint64_t nonce() const { return m_counter; }

  private:
    NoiseKey m_key;
    uint64_t m_counter;
  };

}}}

#endif // MONERO_TREZOR_THP_NOISE_H
