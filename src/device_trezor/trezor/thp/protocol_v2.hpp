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

#ifndef MONERO_TREZOR_THP_PROTOCOL_V2_H
#define MONERO_TREZOR_THP_PROTOCOL_V2_H

#include "../transport.hpp"
#include "channel.hpp"
#include "noise.hpp"

#include <memory>

namespace hw { namespace trezor { namespace thp {

  // Trezor's reported state byte from HandshakeCompletionResponse.
  // Per specification.md these are the only documented values.
  constexpr uint8_t STATE_UNPAIRED            = 0x00;
  constexpr uint8_t STATE_PAIRED              = 0x01;
  constexpr uint8_t STATE_PAIRED_AUTOCONNECT  = 0x02;

  // ProtocolV2 implements the Protocol interface (write/read of protobuf
  // messages) on top of the THP wire format. Unlike ProtocolV1 it is
  // stateful: a single instance is bound to one device session for the
  // lifetime of an open connection.
  //
  // Lifecycle:
  //   1. set_host_static_key() / set_known_devices()  (before session_begin)
  //   2. session_begin(transport) -> alloc, handshake, [pairing]
  //   3. write/read pairs        -> AES-GCM-sealed protobuf exchange
  //   4. session_end(transport)
  class ProtocolV2 : public Protocol {
  public:
    ProtocolV2();
    ~ProtocolV2() override = default;

    // Provide the host's persistent X25519 keypair (loaded from disk or
    // freshly generated). MUST be called before session_begin.
    void set_host_static_key(const HostStaticKey &key);

    // Provide previously-paired devices. May be empty for first-time pairing.
    void set_known_devices(std::vector<KnownDevice> known);

    // Skip the channel allocation step on session_begin; reuse the
    // allocation that the probe already obtained.  Used by
    // ProtocolAutoDetect; callers that go straight to ProtocolV2 should
    // not need this.
    void adopt_allocation(const AllocatedChannel &allocation);

    // Read-only access to the host static keypair currently in use
    // (either the value passed to set_host_static_key or, in TOFU mode,
    // a freshly-generated one).
    const HostStaticKey &host_static() const { return m_host_static; }

    void session_begin(Transport &transport) override;
    void session_end  (Transport &transport) override;

    void write(Transport &transport,
               const google::protobuf::Message &req) override;
    void read (Transport &transport,
               std::shared_ptr<google::protobuf::Message> &msg,
               messages::MessageType *msg_type = nullptr) override;

    // For diagnostics / pairing UX.
    uint16_t                      channel_id()             const { return m_channel.channel_id; }
    const std::vector<uint8_t>   &device_properties()      const { return m_channel.device_properties_pb; }
    const NoisePubKey            &trezor_masked_static()   const { return m_handshake.trezor_masked_static_pubkey(); }
    uint8_t                       trezor_state()           const { return m_handshake.trezor_state(); }
    bool                          is_known_device()        const { return m_handshake.is_known_device(); }

  private:
    // Send a transport-layer frame and (for sequence-bearing frames) wait
    // for the device's ACK. The control byte's sequence bit is updated
    // automatically based on the alternating-bit state.
    void send_frame(Transport &transport, uint8_t control_byte,
                    const uint8_t *payload, size_t payload_len);

    // Read a transport-layer frame, sending an ACK back if the frame
    // bears a sequence bit. Returns the received Frame (with payload
    // already validated for CRC by the assembler).
    Frame recv_frame(Transport &transport);

    AllocatedChannel  m_channel;
    bool              m_have_allocation = false;
    NoiseXxInitiator  m_handshake;
    HostStaticKey     m_host_static{};
    bool              m_have_host_static = false;
    std::vector<KnownDevice> m_known_devices;
    std::unique_ptr<TransportCipher> m_send_cipher;
    std::unique_ptr<TransportCipher> m_recv_cipher;
    uint8_t           m_send_seq = 0; // alternating bit
    uint8_t           m_recv_seq = 0; // alternating bit
    bool              m_session_open = false;
  };

}}}

#endif // MONERO_TREZOR_THP_PROTOCOL_V2_H
