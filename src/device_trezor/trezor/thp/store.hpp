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

#ifndef MONERO_TREZOR_THP_STORE_H
#define MONERO_TREZOR_THP_STORE_H

#include "noise.hpp"

#include <string>
#include <vector>

namespace hw { namespace trezor { namespace thp {

  // Disk-backed cache of the host's static X25519 keypair and any THP
  // pairing credentials previously issued by Trezor devices.  Stored as
  // a small protobuf-like binary file under the user's monero data
  // directory (~/.bitmonero/trezor/thp_store.bin on Linux,
  // %APPDATA%\Monero\trezor\thp_store.bin on Windows etc), readable
  // only by the user (mode 0600 on POSIX).
  //
  // Layout (all field-prefixed; unknown fields are skipped on load so
  // the file format can grow):
  //   field 1: bytes  host_static_pub  (32)
  //   field 2: bytes  host_static_priv (32)
  //   field 3: repeated KnownDeviceRec
  //
  // KnownDeviceRec:
  //   field 1: bytes  trezor_masked_static_pubkey (32)
  //   field 2: bytes  pairing_credential (variable)
  //
  // The host static private key is written to disk in plaintext.  This
  // matches the existing Trezor v1 flow, which stores the host's
  // hardware-wallet-related state without additional encryption.  The
  // attack surface is "an attacker with read access to your wallet
  // directory can read your wallet too" — the THP credentials don't
  // raise that bar.
  class ThpStore {
  public:
    ThpStore() = default;

    // Loads the file from `path`, creating the empty initial state if it
    // does not exist.  Throws on read errors or malformed contents.
    void load_or_init(const std::string &path);

    // Atomically writes the current state to `path` (write to .tmp, fsync,
    // rename).  Sets POSIX mode 0600.
    void save(const std::string &path) const;

    const HostStaticKey            &host_static()    const { return m_host_static; }
    const std::vector<KnownDevice> &known_devices()  const { return m_known_devices; }

    // Replace or insert a known device by its masked-static-pubkey key.
    void upsert_known_device(const KnownDevice &kd);

    // Set host static key (called once when an empty store is initialised).
    void set_host_static(const HostStaticKey &key) { m_host_static = key; }

    // Default location under the project's wallet data directory.  The
    // higher level (device_trezor_base) supplies `wallet_dir` so the
    // store is per-user, not per-wallet (a single user with multiple
    // wallets shares pairing credentials with their Trezor).
    static std::string default_path(const std::string &wallet_dir);

  private:
    HostStaticKey              m_host_static{};
    std::vector<KnownDevice>   m_known_devices;
    bool                       m_have_host_static = false;
  };

}}}

#endif // MONERO_TREZOR_THP_STORE_H
