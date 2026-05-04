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

#ifndef MONERO_TREZOR_THP_CHANNEL_H
#define MONERO_TREZOR_THP_CHANNEL_H

#include <cstdint>
#include <vector>

namespace hw { namespace trezor {
  class Transport; // forward decl
}}

namespace hw { namespace trezor { namespace thp {

  // Information returned by the device in a ChannelAllocationResponse.
  // The "device_properties" is an opaque protobuf payload (DeviceProperties
  // from trezor-firmware) that the higher protocol layer can decode.
  struct AllocatedChannel {
    uint16_t channel_id = 0;      // Allocated CID (in 0x0001..0xFFEF range)
    std::vector<uint8_t> nonce;   // 8-byte nonce echoed by device
    std::vector<uint8_t> device_properties_pb; // protobuf-encoded properties
  };

  // Allocate a new channel on the broadcast CID 0xFFFF. The host generates
  // an 8-byte nonce, sends a CTRL_CHANNEL_ALLOC_REQUEST, and expects the
  // device to reply with a CTRL_CHANNEL_ALLOC_RESPONSE echoing the nonce
  // and assigning a CID.
  //
  // `timeout_ms` is the per-chunk read deadline used to wait for the
  // device's response.  Set this to a short value (e.g. 3000) when used
  // as part of the v1/v2 protocol probe so a non-THP device's silence
  // doesn't hang the caller.  Default 0 keeps the transport's default
  // (unbounded for USB, ~10s for UDP).
  //
  // Reads/writes are performed via Transport::write_chunk / read_chunk.
  AllocatedChannel allocate_channel(Transport &transport, unsigned int timeout_ms = 0);

}}}

#endif // MONERO_TREZOR_THP_CHANNEL_H
