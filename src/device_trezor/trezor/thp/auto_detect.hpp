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

#ifndef MONERO_TREZOR_THP_AUTO_DETECT_H
#define MONERO_TREZOR_THP_AUTO_DETECT_H

#include "../transport.hpp"
#include "channel.hpp"
#include "noise.hpp"
#include "pairing.hpp"
#include "protocol_v2.hpp"

#include <functional>
#include <memory>
#include <string>

namespace hw { namespace trezor { namespace thp {

  // Pairing UI hook: invoked by ProtocolAutoDetect when a fresh THP
  // device requires CodeEntry pairing.  The host (GUI) renders a modal
  // asking the user for the 6-digit code shown on the Trezor; the
  // returned string is the code.  Throws on user cancel — that aborts
  // the pairing flow and the channel is closed.
  using PairingPromptHook = std::function<std::string()>;

  // Configuration plumbed into ProtocolAutoDetect from the device-glue
  // layer.  All fields are optional except `pairing_prompt`, which must
  // be non-null on first-time pairing.
  struct ProtocolConfig {
    std::string         host_name      = "Monero Wallet";
    std::string         app_name       = "monero-wallet-gui";
    PairingPromptHook   pairing_prompt;
    // Path to the host static key + credentials store (created if absent).
    // If empty, the host static key is generated fresh per session and not
    // persisted (TOFU + no recognition of returning devices).
    std::string         store_path;
  };

  // ProtocolAutoDetect defers protocol selection (v1 vs v2) until the
  // first session_begin.  It probes the device by attempting a THP
  // ChannelAllocationRequest.  If that succeeds, it transitions to
  // ProtocolV2 (running the handshake, persisted-key lookup, and — on
  // the unpaired path — the CodeEntry pairing FSM).  If the probe times
  // out or returns a non-THP response, it falls back to ProtocolV1
  // transparently.
  //
  // Lifecycle and threading match the existing Protocol contract: a
  // single instance is bound to one open transport for the lifetime
  // of the session.
  class ProtocolAutoDetect : public Protocol {
  public:
    ProtocolAutoDetect();
    ~ProtocolAutoDetect() override;

    // Caller wires up the GUI prompt and the persistent store path
    // before session_begin.  May be called repeatedly until then.
    void configure(const ProtocolConfig &config);

    void session_begin(Transport &transport) override;
    void session_end  (Transport &transport) override;
    void write(Transport &transport,
               const google::protobuf::Message &req) override;
    void read (Transport &transport,
               std::shared_ptr<google::protobuf::Message> &msg,
               messages::MessageType *msg_type = nullptr) override;

    // After session_begin, returns "v1" or "v2".  Used by tests and
    // diagnostics; not part of the Protocol contract.
    const char *selected_protocol() const { return m_selected; }

  private:
    // Attempt a THP channel-allocation handshake; returns the
    // allocated channel on success, throws on any failure.  The
    // caller swallows the throw and falls back to v1.
    AllocatedChannel probe_thp(Transport &transport);

    // Drive the pairing FSM via the configured prompt.  Sends/receives
    // pairing messages via `m_v2`'s ProtocolV2 (which already has the
    // post-handshake transport cipherstates set up).
    void run_code_entry_pairing(Transport &transport);

    ProtocolConfig                        m_config;
    std::shared_ptr<Protocol>             m_actual;     // v1 or v2 once selected
    std::shared_ptr<ProtocolV2>           m_v2;         // shortcut typed alias
    const char                           *m_selected = "unknown";
  };

}}}

#endif // MONERO_TREZOR_THP_AUTO_DETECT_H
