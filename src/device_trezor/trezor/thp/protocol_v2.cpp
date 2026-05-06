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

#include "protocol_v2.hpp"
#include "framing.hpp"
#include "../exceptions.hpp"

#include <cstdio>
#include <cstring>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.thp"

namespace hw { namespace trezor { namespace thp {

  ProtocolV2::ProtocolV2() = default;

  void ProtocolV2::send_frame(Transport &transport, uint8_t control_byte,
                              const uint8_t *payload, size_t payload_len)
  {
    auto wire = encode_frame(control_byte, m_channel.channel_id,
                             payload, payload_len);
    for (size_t off = 0; off < wire.size(); off += USB_CHUNK_SIZE) {
      transport.write_chunk(wire.data() + off, USB_CHUNK_SIZE);
    }
  }

  Frame ProtocolV2::recv_frame(Transport &transport)
  {
    FrameAssembler asm_;
    uint8_t chunk[USB_CHUNK_SIZE];
    while (true) {
      const size_t got = transport.read_chunk(chunk, sizeof(chunk));
      if (got != USB_CHUNK_SIZE) {
        throw exc::CommunicationException("THP: short chunk in recv_frame");
      }
      if (asm_.feed_chunk(chunk, USB_CHUNK_SIZE)) {
        return asm_.take();
      }
    }
  }

  void ProtocolV2::set_host_static_key(const HostStaticKey &key)
  {
    m_host_static = key;
    m_have_host_static = true;
  }

  void ProtocolV2::set_known_devices(std::vector<KnownDevice> known)
  {
    m_known_devices = std::move(known);
  }

  void ProtocolV2::adopt_allocation(const AllocatedChannel &allocation)
  {
    m_channel         = allocation;
    m_have_allocation = true;
  }

  void ProtocolV2::session_begin(Transport &transport) {
    if (m_session_open) {
      return;
    }
    if (!m_have_host_static) {
      // No persisted host static key was provided. Fall back to a
      // freshly-generated keypair so the unpaired (TOFU) flow can
      // proceed; the device-glue layer should persist this and pass
      // it back via set_host_static_key on subsequent sessions to
      // enable paired-device recognition.
      MWARNING("THP: no persisted host static key; generating a fresh one (TOFU)");
      crypto::x25519_keypair(m_host_static.pub, m_host_static.priv);
      m_have_host_static = true;
    }

    // 1. Channel allocation on the broadcast CID — unless the auto-detect
    //    layer already did it as part of the probe.
    if (!m_have_allocation) {
      m_channel = allocate_channel(transport);
    }
    MWARNING("THP: allocated channel " << m_channel.channel_id);

    // 2. Wire device properties + persisted credentials into the handshake.
    m_handshake.set_device_properties(m_channel.device_properties_pb.data(),
                                      m_channel.device_properties_pb.size());
    m_handshake.set_host_static_key(m_host_static);
    m_handshake.set_known_devices(m_known_devices);

    // Per THP spec (docs/common/thp/specification.md):
    //  - Message-type mask is 0xE7 (bit 3 = seq, bit 4 = piggyback ACK).
    //  - ACK-type mask is 0xF7 (bit 3 = seq).
    // We compare under those masks so a piggybacked ACK on a handshake
    // response, or a vendor-quirk variant, doesn't trip the matcher.
    constexpr uint8_t MSG_TYPE_MASK = 0xE7;
    constexpr uint8_t ACK_TYPE_MASK = 0xF7;
    auto hex2 = [](uint8_t b){ char s[5]; std::snprintf(s, sizeof(s), "%02x", b); return std::string(s); };

    auto recv_specific = [&](uint8_t want_base, const char *what) -> Frame {
      while (true) {
        Frame fr = recv_frame(transport);
        MWARNING("THP: rx ctrl=0x" << hex2(fr.control_byte)
               << " cid=0x" << std::hex << fr.channel_id << std::dec
               << " len=" << fr.payload.size()
               << " (waiting for " << what << ")");
        if (fr.channel_id != m_channel.channel_id) {
          MWARNING("THP: dropping frame on unexpected channel " << fr.channel_id);
          continue;
        }
        if ((fr.control_byte & MSG_TYPE_MASK) == (want_base & MSG_TYPE_MASK)) {
          return fr;
        }
        if (fr.is_ack()) {
          MWARNING("THP: stray ACK 0x" << hex2(fr.control_byte) << " while waiting for " << what);
          continue;
        }
        if (fr.control_byte == CTRL_TRANSPORT_ERROR) {
          throw exc::ProtocolException(std::string("THP: transport error during ") + what);
        }
        throw exc::ProtocolException(std::string("THP: unexpected frame waiting for ") + what +
                                     " (got control 0x" + hex2(fr.control_byte) + ")");
      }
    };

    auto consume_ack = [&](uint8_t want_seq, const char *what) {
      const uint8_t want_ctrl = want_seq ? CTRL_ACK_SEQ1 : CTRL_ACK_SEQ0;
      while (true) {
        Frame fr = recv_frame(transport);
        MWARNING("THP: rx ctrl=0x" << hex2(fr.control_byte)
               << " cid=0x" << std::hex << fr.channel_id << std::dec
               << " (waiting for ACK seq=" << int(want_seq) << " after " << what << ")");
        if (fr.channel_id != m_channel.channel_id) {
          continue;
        }
        if ((fr.control_byte & ACK_TYPE_MASK) == want_ctrl) {
          return;
        }
        if (fr.is_ack()) {
          MWARNING("THP: ignoring ACK 0x" << hex2(fr.control_byte) << " (wrong seq) after " << what);
          continue;
        }
        throw exc::ProtocolException(std::string("THP: expected ACK after ") + what +
                                     " (got control 0x" + hex2(fr.control_byte) + ")");
      }
    };

    MINFO("THP: starting handshake on channel " << m_channel.channel_id);

    // 3. host -> device: HandshakeInitiationRequest (base 0x00, seq=0).
    auto init_req = m_handshake.build_init_request(/*try_to_unlock=*/false);
    MWARNING("THP: tx HandshakeInitRequest len=" << init_req.size());
    send_frame(transport, CTRL_HANDSHAKE_INIT_REQ,
               init_req.data(), init_req.size());
    // 3a. device ACKs the request (seq=0).
    consume_ack(0, "HandshakeInitRequest");

    // 4. device -> host: HandshakeInitiationResponse (base 0x01, device seq=0).
    Frame init_resp = recv_specific(CTRL_HANDSHAKE_INIT_RESP, "HandshakeInitResponse");
    m_handshake.consume_init_response(init_resp.payload.data(),
                                      init_resp.payload.size());
    // 4a. host ACKs the response (seq=0).
    send_frame(transport, CTRL_ACK_SEQ0, nullptr, 0);

    // 5. host -> device: HandshakeCompletionRequest (base 0x02, seq=1 → wire 0x0A).
    auto comp_req = m_handshake.build_completion_request();
    MWARNING("THP: tx HandshakeCompletionRequest len=" << comp_req.size() << " ctrl=0x0a");
    send_frame(transport, CTRL_HANDSHAKE_COMP_REQ | CTRL_SEQ_BIT,
               comp_req.data(), comp_req.size());
    // 5a. device ACKs (seq=1).
    consume_ack(1, "HandshakeCompletionRequest");

    // 6. device -> host: HandshakeCompletionResponse (base 0x03, device seq=1 → wire 0x0B).
    Frame comp_resp = recv_specific(CTRL_HANDSHAKE_COMP_RESP, "HandshakeCompletionResponse");
    m_handshake.consume_completion_response(comp_resp.payload.data(),
                                            comp_resp.payload.size());
    // 6a. host ACKs (seq=1).
    send_frame(transport, CTRL_ACK_SEQ1, nullptr, 0);

    MINFO("THP: handshake complete on channel " << m_channel.channel_id);

    // 7. Build cipherstates per specification.md (encryption_state: nonce
    //    counters start at 0 for outgoing requests and 1 for incoming
    //    responses, since the HandshakeCompletionResponse already consumed
    //    the response counter at 0).
    const HandshakeKeys &keys = m_handshake.keys();
    m_send_cipher = std::make_unique<TransportCipher>(keys.key_request,  /*nonce=*/0);
    m_recv_cipher = std::make_unique<TransportCipher>(keys.key_response, /*nonce=*/1);
    m_send_seq = 0;
    m_recv_seq = 0;

    if (!m_handshake.is_known_device() &&
        m_handshake.trezor_state() == STATE_UNPAIRED) {
      // First-time pairing is still required to upgrade to an authenticated
      // session. Until the pairing layer is wired up the caller should
      // treat this state as "unauthenticated channel" and drive the
      // pairing FSM (ThpPairingRequest -> ThpSelectMethod -> ...) before
      // sending application traffic.
      MWARNING("THP: device is unpaired; pairing FSM must run before traffic is trusted");
    }
    m_session_open = true;
  }

  void ProtocolV2::session_end(Transport & /*transport*/) {
    m_send_cipher.reset();
    m_recv_cipher.reset();
    m_session_open = false;
  }

  void ProtocolV2::write(Transport &transport,
                         const google::protobuf::Message &req) {
    if (!m_session_open || !m_send_cipher) {
      throw exc::ProtocolException("THP: write before session_begin");
    }

    // Serialize the protobuf message: 2-byte big-endian message wire
    // number followed by the protobuf bytes (per THP encrypted-transport
    // payload format).
    const uint16_t wire_num = MessageMapper::get_message_wire_number(req);
#if GOOGLE_PROTOBUF_VERSION < 3006001
    const size_t msg_size = req.ByteSize();
#else
    const size_t msg_size = req.ByteSizeLong();
#endif
    std::vector<uint8_t> plain;
    plain.resize(2 + msg_size);
    write_be16(plain.data(), wire_num);
    if (!req.SerializeToArray(plain.data() + 2, msg_size)) {
      throw exc::EncodingException("THP: protobuf serialize failed");
    }

    std::vector<uint8_t> sealed;
    m_send_cipher->seal(/*aad=*/nullptr, /*aad_len=*/0,
                        plain.data(), plain.size(), sealed);

    const uint8_t control = CTRL_ENCRYPTED_TRANSPORT |
                            (m_send_seq ? CTRL_SEQ_BIT : 0);
    send_frame(transport, control, sealed.data(), sealed.size());

    // Wait for the device's ACK on the alternating bit. Real impls would
    // also handle retransmission on timeout; here we just block.
    Frame ack = recv_frame(transport);
    const uint8_t want_ack = m_send_seq ? CTRL_ACK_SEQ1 : CTRL_ACK_SEQ0;
    if (ack.control_byte != want_ack || ack.channel_id != m_channel.channel_id) {
      throw exc::ProtocolException("THP: missing or mismatched ACK after write");
    }
    m_send_seq ^= 1;
  }

  void ProtocolV2::read(Transport &transport,
                        std::shared_ptr<google::protobuf::Message> &msg,
                        messages::MessageType *msg_type) {
    if (!m_session_open || !m_recv_cipher) {
      throw exc::ProtocolException("THP: read before session_begin");
    }

    Frame f = recv_frame(transport);
    if ((f.control_byte & 0xF7) != CTRL_ENCRYPTED_TRANSPORT ||
        f.channel_id != m_channel.channel_id) {
      throw exc::ProtocolException("THP: read got unexpected frame type");
    }
    const uint8_t got_seq = f.sequence_bit();
    if (got_seq != m_recv_seq) {
      throw exc::ProtocolException("THP: out-of-order encrypted frame");
    }

    std::vector<uint8_t> plain;
    if (!m_recv_cipher->open(/*aad=*/nullptr, /*aad_len=*/0,
                             f.payload.data(), f.payload.size(), plain)) {
      throw exc::SecurityException("THP: AES-GCM decrypt failed");
    }
    if (plain.size() < 2) {
      throw exc::ProtocolException("THP: decrypted payload too small");
    }
    const uint16_t wire_num = read_be16(plain.data());

    std::shared_ptr<google::protobuf::Message> wrap(MessageMapper::get_message(wire_num));
    if (!wrap->ParseFromArray(plain.data() + 2, plain.size() - 2)) {
      throw exc::EncodingException("THP: protobuf parse failed");
    }
    msg = wrap;
    if (msg_type) {
      *msg_type = static_cast<messages::MessageType>(wire_num);
    }

    // ACK the frame.
    const uint8_t ack_ctrl = m_recv_seq ? CTRL_ACK_SEQ1 : CTRL_ACK_SEQ0;
    send_frame(transport, ack_ctrl, nullptr, 0);
    m_recv_seq ^= 1;
  }

}}}
