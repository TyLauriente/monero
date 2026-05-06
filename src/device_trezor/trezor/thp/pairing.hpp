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

#ifndef MONERO_TREZOR_THP_PAIRING_H
#define MONERO_TREZOR_THP_PAIRING_H

#include "noise.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace hw { namespace trezor { namespace thp {

  // Elligator2 map for Curve25519 (per RFC 9380 §G.2.1 / IRTF
  // draft-irtf-cfrg-cpace-10 §"CPaceMontgomery"). Maps a uniform 32-byte
  // input to a Curve25519 u-coordinate. Used as the password-binding
  // step of CPace during the THP CodeEntry pairing flow.
  //
  // The input `r_bytes` is interpreted little-endian and reduced mod
  // p = 2^255 - 19. The output is encoded little-endian as the u-coordinate.
  void elligator2_curve25519(const uint8_t r_bytes[32], uint8_t out_u[32]);

  // CPace "generator" derivation per the THP spec, exactly matching the
  // IRTF CPACE-X25519-SHA512 symmetric-setting suite:
  //   pregenerator = SHA-512(prefix || code || padding || handshake_hash || 0x00)[:32]
  //   generator    = ELLIGATOR2(pregenerator)
  // where `prefix` and `padding` are the THP-specified constants documented
  // in specification.md §"Notes" under "Code Entry pairing sequence".
  //
  // `code` should be the user-entered code rendered as ASCII digits with
  // no separators (e.g. "123456" — six bytes for the standard six-digit
  // code).  `handshake_hash` is the post-handshake h value, exactly 32 bytes.
  void cpace_derive_generator(const std::string &code,
                              const NoiseHash    &handshake_hash,
                              uint8_t out_generator[32]);

  // ---------------------------------------------------------------------------
  // CodeEntry pairing FSM driver, host-side. Walks states HP1 -> HP2 -> HP3a
  // -> HP4 -> HP5 -> HC0 from specification.md.
  //
  // The user (or the GUI sitting on top) drives the FSM by calling the
  // build_*() and consume_*() methods in sequence. The pairing-code prompt
  // is delivered via a callback supplied by the caller.
  // ---------------------------------------------------------------------------
  class CodeEntryPairing {
  public:
    // Set the post-handshake hash and the pairing-method byte that the
    // device assigned (always 0x02 / CodeEntry for this driver).
    explicit CodeEntryPairing(const NoiseHash &handshake_hash);

    // Wipe all sensitive members on destruction (CPace private key,
    // shared secret, code).
    ~CodeEntryPairing();

    // HP0 -> HP1: build the ThpPairingRequest payload (host_name, app_name).
    // The two strings are written into a protobuf-encoded body.
    static std::vector<uint8_t> build_pairing_request(const std::string &host_name,
                                                      const std::string &app_name);

    // HP1 -> HP2: build the ThpSelectMethod[CodeEntry] payload.
    static std::vector<uint8_t> build_select_method_code_entry();

    // HP2 -> HP3a: consume ThpCodeEntryCommitment (32-byte commitment),
    // generate a random 16-byte challenge, and return the
    // ThpCodeEntryChallenge payload.
    std::vector<uint8_t> consume_commitment_build_challenge(const uint8_t *commitment, size_t len);

    // HP3a -> HP4: consume ThpCodeEntryCpaceTrezor.
    void consume_cpace_trezor(const uint8_t *cpace_trezor_pub, size_t len);

    // HP4 -> HP5: build the ThpCodeEntryCpaceHostTag payload from the
    // user-entered `code` (ASCII digits — the host's GUI prompts for it).
    std::vector<uint8_t> build_host_tag(const std::string &code);

    // HP5 -> HC0: consume ThpCodeEntrySecret. Verifies (a) the commitment
    // matches SHA-256(secret), and (b) the user-entered code matches the
    // SHA-256 derivation per the spec. Returns true on success.
    bool consume_secret(const uint8_t *secret, size_t len);

    bool is_paired() const { return m_paired; }

    // Accessors used by tests and the credential phase.
    const std::array<uint8_t, 16> &challenge()         const { return m_challenge; }
    const std::array<uint8_t, 32> &commitment()        const { return m_commitment; }
    const std::array<uint8_t, 32> &cpace_trezor_pub()  const { return m_cpace_trezor_pub; }

  private:
    NoiseHash                m_h{};
    std::array<uint8_t, 16>  m_challenge{};
    std::array<uint8_t, 32>  m_commitment{};
    std::array<uint8_t, 32>  m_cpace_trezor_pub{};
    std::array<uint8_t, 32>  m_cpace_host_priv{};
    std::array<uint8_t, 32>  m_cpace_host_pub{};
    std::array<uint8_t, 32>  m_shared_secret{};
    std::string              m_code;
    bool                     m_have_commitment   = false;
    bool                     m_have_trezor_pub   = false;
    bool                     m_have_host_tag     = false;
    bool                     m_paired            = false;
  };

  // The host sends the pairing "code prompt" up to the GUI via this
  // callback. The GUI displays an input modal and returns the digits
  // the user typed in. Must run on a thread that can block on user
  // input. Throws on user cancel.
  using PairingCodePrompt = std::function<std::string()>;

}}}

#endif // MONERO_TREZOR_THP_PAIRING_H
