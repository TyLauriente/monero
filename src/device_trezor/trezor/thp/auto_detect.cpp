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

#include "auto_detect.hpp"
#include "framing.hpp"
#include "store.hpp"
#include "../exceptions.hpp"
#include "../messages_map.hpp"
#include "../messages/messages-thp.pb.h"
#include "../messages/messages-common.pb.h"

#include <cstring>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.thp"

namespace hw { namespace trezor { namespace thp {

  ProtocolAutoDetect::ProtocolAutoDetect() = default;
  ProtocolAutoDetect::~ProtocolAutoDetect() = default;

  void ProtocolAutoDetect::configure(const ProtocolConfig &config)
  {
    m_config = config;
  }

  AllocatedChannel ProtocolAutoDetect::probe_thp(Transport &transport)
  {
    // The channel allocation routine handles the full request/response
    // cycle.  If the device is V1 it will not respond to our THP frame
    // and the read times out via the underlying transport (3-second
    // probe deadline — Safe 7 responds in milliseconds in practice).
    return allocate_channel(transport, /*timeout_ms=*/3000);
  }

  void ProtocolAutoDetect::session_begin(Transport &transport)
  {
    if (m_actual) {
      // Already opened.
      m_actual->session_begin(transport);
      return;
    }

    // Load the persistent THP store, if a path was configured.  This
    // gives us the host static key and any prior pairing credentials.
    ThpStore store;
    bool have_store_path = !m_config.store_path.empty();
    if (have_store_path) {
      store.load_or_init(m_config.store_path);
    }

    // Probe the device by attempting a THP channel allocation.  If the
    // device is THP-only (Safe 7) this succeeds in milliseconds; if the
    // device is V1 (Model T / Safe 3 / Safe 5) it ignores the unknown
    // packet, the read times out, and probe_thp throws TimeoutException.
    //
    // We deliberately catch *only* TimeoutException to fall back to V1.
    // Other failures (libusb stalls, encoding errors, security failures)
    // signal a real problem and must propagate, otherwise the user sees
    // a confusing "V1 failure" on a Safe 7 that actually has a
    // communication issue.
    AllocatedChannel allocation;
    try {
      allocation = probe_thp(transport);
    } catch (const exc::TimeoutException &e) {
      MDEBUG("THP probe timed out (" << e.what() << "); falling back to ProtocolV1");
      m_actual   = std::make_shared<ProtocolV1>();
      m_selected = "v1";
      return;
    }

    MINFO("THP detected on channel " << allocation.channel_id);
    auto v2 = std::make_shared<ProtocolV2>();

    // Decide on host static key + known devices to feed the handshake.
    if (have_store_path) {
      HostStaticKey host_static = store.host_static();
      if (host_static.pub == NoisePubKey{} || host_static.priv == NoisePrivKey{}) {
        crypto::x25519_keypair(host_static.pub, host_static.priv);
        store.set_host_static(host_static);
        store.save(m_config.store_path);
      }
      v2->set_host_static_key(host_static);
      v2->set_known_devices(store.known_devices());
    }

    v2->adopt_allocation(allocation);
    v2->session_begin(transport);

    // We do NOT promote `v2` to `m_actual` until the full unpaired-or-paired
    // routing decision is made and any pairing FSM has succeeded. If
    // session_begin() succeeded but pairing then throws, m_actual must
    // remain null so the next session_begin() retries from scratch
    // rather than short-circuiting on the cached partial state.
    auto promote = [&]() {
      m_actual   = v2;
      m_selected = "v2";
    };

    if (v2->trezor_state() == STATE_UNPAIRED) {
      if (!m_config.pairing_prompt) {
        // STATE_UNPAIRED with no prompt configured: fail closed; the
        // application traffic phase isn't trustworthy without pairing.
        throw exc::SecurityException(
            "THP: device is unpaired and no pairing prompt is configured "
            "(set ProtocolConfig::pairing_prompt before session_begin)");
      }
      // Make m_v2 visible to run_code_entry_pairing; clear it on any
      // failure so the next reconnect starts clean.
      m_v2 = v2;
      try {
        run_code_entry_pairing(transport);
      } catch (...) {
        m_v2.reset();
        throw;
      }

      if (have_store_path) {
        const auto &hs = v2->host_static();
        messages::thp::ThpCredentialRequest creq;
        creq.set_host_static_public_key(reinterpret_cast<const char *>(hs.pub.data()),
                                        hs.pub.size());
        v2->write(transport, creq);

        std::shared_ptr<google::protobuf::Message> resp_msg;
        messages::MessageType msg_type;
        v2->read(transport, resp_msg, &msg_type);
        auto cresp = std::dynamic_pointer_cast<messages::thp::ThpCredentialResponse>(resp_msg);
        if (auto fail = std::dynamic_pointer_cast<messages::common::Failure>(resp_msg)) {
          throw exc::proto::FailureException(
              fail->has_code() ? boost::optional<uint32_t>(fail->code())
                               : boost::optional<uint32_t>(),
              fail->has_message() ? boost::optional<std::string>(fail->message())
                                  : boost::optional<std::string>());
        }
        if (!cresp) {
          throw exc::ProtocolException("THP: expected ThpCredentialResponse");
        }

        // ThpCredentialResponse delivers the device's *unmasked* static
        // pubkey alongside the credential — that's how we recover it
        // (the InitResponse only carries the masked form). We store the
        // unmasked form so subsequent sessions can recompute the mask
        // against each session's fresh device ephemeral pubkey.
        const std::string &dev_static = cresp->trezor_static_public_key();
        if (dev_static.size() != 32) {
          throw exc::ProtocolException("THP: ThpCredentialResponse: bad trezor_static_public_key size");
        }
        KnownDevice kd;
        std::memcpy(kd.trezor_static_pubkey.data(), dev_static.data(), 32);
        kd.host_static = hs;
        const std::string &cred = cresp->credential();
        kd.pairing_credential.assign(cred.begin(), cred.end());
        store.upsert_known_device(kd);
        store.save(m_config.store_path);

        // Send ThpEndRequest to leave the credential phase.
        messages::thp::ThpEndRequest end_req;
        v2->write(transport, end_req);
        std::shared_ptr<google::protobuf::Message> end_resp;
        v2->read(transport, end_resp, &msg_type);
        if (auto fail = std::dynamic_pointer_cast<messages::common::Failure>(end_resp)) {
          throw exc::proto::FailureException(
              fail->has_code() ? boost::optional<uint32_t>(fail->code())
                               : boost::optional<uint32_t>(),
              fail->has_message() ? boost::optional<std::string>(fail->message())
                                  : boost::optional<std::string>());
        }
        if (!std::dynamic_pointer_cast<messages::thp::ThpEndResponse>(end_resp)) {
          throw exc::ProtocolException("THP: expected ThpEndResponse");
        }
      }
      promote();
    } else if (v2->trezor_state() == STATE_PAIRED ||
               v2->trezor_state() == STATE_PAIRED_AUTOCONNECT) {
      // The device claims a paired session. Trust it only if our store
      // contains a matching unmasked static pubkey (TOFU). A device that
      // reports paired status without a store entry is either a fresh
      // device we somehow lost the credential for, or an attempted spoof.
      if (!v2->is_known_device()) {
        throw exc::SecurityException(
            "THP: device claims paired status but is not in our known-devices "
            "list. The pairing store may have been deleted or the device may "
            "have been swapped. Re-pair the device by clearing "
            ".trezor/thp_store.bin in the wallet directory.");
      }
      promote();
    } else {
      throw exc::ProtocolException(
          "THP: device returned unknown state byte (got " +
          std::to_string(int(v2->trezor_state())) + ")");
    }
  }

  void ProtocolAutoDetect::run_code_entry_pairing(Transport &transport)
  {
    if (!m_v2) {
      throw exc::ProtocolException("THP: pairing without ProtocolV2");
    }

    // Read the next message, transparently ack'ing ButtonRequest, and
    // surface common::Failure as a typed FailureException. `expected`
    // names the message we're waiting for, used in the diagnostic if an
    // unrelated message arrives.
    auto read_handling_buttons = [&](const char *expected) {
      std::shared_ptr<google::protobuf::Message> msg;
      messages::MessageType mt;
      while (true) {
        m_v2->read(transport, msg, &mt);
        if (std::dynamic_pointer_cast<messages::common::ButtonRequest>(msg)) {
          messages::common::ButtonAck ack;
          m_v2->write(transport, ack);
          continue;
        }
        if (auto fail = std::dynamic_pointer_cast<messages::common::Failure>(msg)) {
          throw exc::proto::FailureException(
              fail->has_code() ? boost::optional<uint32_t>(fail->code())
                               : boost::optional<uint32_t>(),
              fail->has_message() ? boost::optional<std::string>(fail->message())
                                  : boost::optional<std::string>(
                                      std::string("THP pairing failed while waiting for ") + expected));
        }
        return msg;
      }
    };

    // 1. Send ThpPairingRequest(host_name, app_name) and wait for
    //    ThpPairingRequestApproved.
    messages::thp::ThpPairingRequest preq;
    preq.set_host_name(m_config.host_name);
    preq.set_app_name(m_config.app_name);
    m_v2->write(transport, preq);
    {
      auto msg = read_handling_buttons("ThpPairingRequestApproved");
      if (!std::dynamic_pointer_cast<messages::thp::ThpPairingRequestApproved>(msg)) {
        throw exc::ProtocolException("THP pairing: unexpected message after PairingRequest");
      }
    }

    // 2. Send ThpSelectMethod(CodeEntry).
    messages::thp::ThpSelectMethod sel;
    sel.set_selected_pairing_method(messages::thp::CodeEntry);
    m_v2->write(transport, sel);

    // 3. Receive ThpCodeEntryCommitment, send ThpCodeEntryChallenge.
    CodeEntryPairing pairing(m_v2->handshake_hash());
    {
      auto msg = read_handling_buttons("ThpCodeEntryCommitment");
      auto cmt = std::dynamic_pointer_cast<messages::thp::ThpCodeEntryCommitment>(msg);
      if (!cmt) throw exc::ProtocolException("THP pairing: expected ThpCodeEntryCommitment");
      const std::string &c = cmt->commitment();
      pairing.consume_commitment_build_challenge(
          reinterpret_cast<const uint8_t *>(c.data()), c.size());
      messages::thp::ThpCodeEntryChallenge ch;
      ch.set_challenge(reinterpret_cast<const char *>(pairing.challenge().data()),
                       pairing.challenge().size());
      m_v2->write(transport, ch);
    }

    // 4. Receive ThpCodeEntryCpaceTrezor.
    {
      auto msg = read_handling_buttons("ThpCodeEntryCpaceTrezor");
      auto ct = std::dynamic_pointer_cast<messages::thp::ThpCodeEntryCpaceTrezor>(msg);
      if (!ct) throw exc::ProtocolException("THP pairing: expected ThpCodeEntryCpaceTrezor");
      const std::string &k = ct->cpace_trezor_public_key();
      pairing.consume_cpace_trezor(reinterpret_cast<const uint8_t *>(k.data()), k.size());
    }

    // 5. Prompt the user for the code, send ThpCodeEntryCpaceHostTag.
    //    An empty return value from the prompt is treated as a user
    //    cancellation — clearer error than feeding empty into the
    //    derivation and getting a CPace tag mismatch.
    std::string code = m_config.pairing_prompt();
    if (code.empty()) {
      throw exc::SecurityException("THP pairing: cancelled by user");
    }
    messages::thp::ThpCodeEntryCpaceHostTag tag_msg;
    auto host_tag_payload = pairing.build_host_tag(code);
    if (!tag_msg.ParseFromArray(host_tag_payload.data(), host_tag_payload.size())) {
      throw exc::EncodingException("THP pairing: failed to re-parse host tag");
    }
    m_v2->write(transport, tag_msg);

    // 6. Receive ThpCodeEntrySecret, verify. If the user typed a wrong
    //    code, Trezor's CPace tag check fails and the device returns
    //    Failure rather than ThpCodeEntrySecret — read_handling_buttons
    //    throws FailureException, which the GUI surfaces as "wrong code,
    //    try again".
    {
      auto msg = read_handling_buttons("ThpCodeEntrySecret");
      auto sec = std::dynamic_pointer_cast<messages::thp::ThpCodeEntrySecret>(msg);
      if (!sec) throw exc::ProtocolException("THP pairing: expected ThpCodeEntrySecret");
      const std::string &s = sec->secret();
      if (!pairing.consume_secret(reinterpret_cast<const uint8_t *>(s.data()), s.size())) {
        throw exc::SecurityException(
            "THP pairing: code mismatch (commitment / SHA-256 verification failed)");
      }
    }

    MINFO("THP CodeEntry pairing succeeded");
  }

  void ProtocolAutoDetect::session_end(Transport &transport)
  {
    if (m_actual) {
      m_actual->session_end(transport);
      m_actual.reset();
      m_v2.reset();
      m_selected = "unknown";
    }
  }

  void ProtocolAutoDetect::write(Transport &transport,
                                 const google::protobuf::Message &req)
  {
    if (!m_actual) {
      throw exc::ProtocolException("THP auto-detect: write before session_begin");
    }
    m_actual->write(transport, req);
  }

  void ProtocolAutoDetect::read(Transport &transport,
                                std::shared_ptr<google::protobuf::Message> &msg,
                                messages::MessageType *msg_type)
  {
    if (!m_actual) {
      throw exc::ProtocolException("THP auto-detect: read before session_begin");
    }
    m_actual->read(transport, msg, msg_type);
  }

}}}
