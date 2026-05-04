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

#include "channel.hpp"
#include "framing.hpp"
#include "../exceptions.hpp"
#include "../transport.hpp"

#include <sodium/randombytes.h>
#include <cstring>

namespace hw { namespace trezor { namespace thp {

  static constexpr size_t NONCE_BYTES = 8;
  static constexpr size_t ALLOC_RESPONSE_FIXED_BYTES = NONCE_BYTES + sizeof(uint16_t);

  AllocatedChannel allocate_channel(Transport &transport, unsigned int timeout_ms)
  {
    // 1. Build ChannelAllocationRequest body: random 8-byte nonce.
    AllocatedChannel out;
    out.nonce.resize(NONCE_BYTES);
    randombytes_buf(out.nonce.data(), out.nonce.size());

    // 2. Encode and write the broadcast frame.
    auto wire = encode_frame(CTRL_CHANNEL_ALLOC_REQUEST, CID_BROADCAST,
                             out.nonce.data(), out.nonce.size());
    for (size_t off = 0; off < wire.size(); off += USB_CHUNK_SIZE) {
      transport.write_chunk(wire.data() + off, USB_CHUNK_SIZE);
    }

    // 3. Read chunks back and reassemble until we have a full response.
    FrameAssembler asm_;
    uint8_t chunk[USB_CHUNK_SIZE];
    while (true) {
      const size_t got = (timeout_ms != 0)
          ? transport.read_chunk(chunk, sizeof(chunk), timeout_ms)
          : transport.read_chunk(chunk, sizeof(chunk));
      if (got != USB_CHUNK_SIZE) {
        throw exc::CommunicationException("THP: short chunk during channel allocation");
      }
      if (asm_.feed_chunk(chunk, USB_CHUNK_SIZE)) {
        break;
      }
    }
    Frame f = asm_.take();

    // 4. Validate response.
    if (f.channel_id != CID_BROADCAST) {
      throw exc::CommunicationException("THP: alloc response not on broadcast channel");
    }
    if (f.control_byte != CTRL_CHANNEL_ALLOC_RESPONSE) {
      throw exc::CommunicationException("THP: unexpected control byte in alloc response");
    }
    if (f.payload.size() < ALLOC_RESPONSE_FIXED_BYTES) {
      throw exc::CommunicationException("THP: alloc response truncated");
    }
    if (std::memcmp(f.payload.data(), out.nonce.data(), NONCE_BYTES) != 0) {
      throw exc::CommunicationException("THP: alloc response nonce mismatch");
    }
    out.channel_id = read_be16(f.payload.data() + NONCE_BYTES);
    if (out.channel_id == CID_INVALID || out.channel_id >= CID_RESERVED_LOW) {
      throw exc::CommunicationException("THP: device returned reserved CID");
    }

    // The remaining bytes are the protobuf-encoded device properties; the
    // caller (ProtocolV2) decodes them lazily.
    if (f.payload.size() > ALLOC_RESPONSE_FIXED_BYTES) {
      out.device_properties_pb.assign(f.payload.begin() + ALLOC_RESPONSE_FIXED_BYTES,
                                      f.payload.end());
    }

    return out;
  }

}}}
