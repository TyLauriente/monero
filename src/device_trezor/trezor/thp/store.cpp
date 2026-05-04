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

#include "store.hpp"
#include "../exceptions.hpp"

#include <boost/filesystem.hpp>

#include <fstream>
#include <sstream>
#include <stdexcept>

#if !defined(_WIN32)
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace hw { namespace trezor { namespace thp {

  // ---------------------------------------------------------------------------
  // Tiny tag-prefixed binary serialisation helpers.  Each record begins
  // with a 1-byte tag, then a varint length, then `length` bytes.  This
  // gives us a forward-compatible layout without pulling in protobuf for
  // the on-disk format.  Tag 0 marks end-of-stream.
  // ---------------------------------------------------------------------------
  namespace {

    constexpr uint8_t TAG_END                       = 0;
    constexpr uint8_t TAG_HOST_STATIC_PUB           = 1;
    constexpr uint8_t TAG_HOST_STATIC_PRIV          = 2;
    constexpr uint8_t TAG_KNOWN_DEVICE              = 3;
    // Inside KNOWN_DEVICE blob:
    constexpr uint8_t KD_TAG_END                    = 0;
    constexpr uint8_t KD_TAG_MASKED_STATIC          = 1;
    constexpr uint8_t KD_TAG_PAIRING_CREDENTIAL     = 2;
    constexpr uint8_t KD_TAG_HOST_STATIC_PUB        = 3;
    constexpr uint8_t KD_TAG_HOST_STATIC_PRIV       = 4;
    // Magic header so we recognise the file across format bumps.
    static constexpr uint8_t MAGIC[8] = {
      'M','T','H','P','S','T','R','1'
    };

    void write_varint(std::vector<uint8_t> &buf, uint64_t v) {
      while (v >= 0x80) { buf.push_back(uint8_t((v & 0x7F) | 0x80)); v >>= 7; }
      buf.push_back(uint8_t(v));
    }

    bool read_varint(const std::vector<uint8_t> &buf, size_t &off, uint64_t &v) {
      v = 0; int shift = 0;
      while (off < buf.size()) {
        uint8_t b = buf[off++];
        v |= uint64_t(b & 0x7F) << shift;
        if ((b & 0x80) == 0) return true;
        shift += 7;
        if (shift > 63) return false;
      }
      return false;
    }

    void write_record(std::vector<uint8_t> &buf, uint8_t tag,
                      const uint8_t *data, size_t len) {
      buf.push_back(tag);
      write_varint(buf, len);
      buf.insert(buf.end(), data, data + len);
    }

    std::vector<uint8_t> serialise(const HostStaticKey &host,
                                   const std::vector<KnownDevice> &known)
    {
      std::vector<uint8_t> buf;
      buf.insert(buf.end(), MAGIC, MAGIC + sizeof(MAGIC));

      write_record(buf, TAG_HOST_STATIC_PUB,  host.pub.data(),  host.pub.size());
      write_record(buf, TAG_HOST_STATIC_PRIV, host.priv.data(), host.priv.size());

      for (const auto &kd : known) {
        // Build inner blob, then write as a length-delimited record.
        std::vector<uint8_t> inner;
        write_record(inner, KD_TAG_MASKED_STATIC,
                     kd.trezor_masked_static_pubkey.data(),
                     kd.trezor_masked_static_pubkey.size());
        write_record(inner, KD_TAG_HOST_STATIC_PUB,
                     kd.host_static.pub.data(),  kd.host_static.pub.size());
        write_record(inner, KD_TAG_HOST_STATIC_PRIV,
                     kd.host_static.priv.data(), kd.host_static.priv.size());
        write_record(inner, KD_TAG_PAIRING_CREDENTIAL,
                     kd.pairing_credential.data(),
                     kd.pairing_credential.size());
        inner.push_back(KD_TAG_END);
        write_record(buf, TAG_KNOWN_DEVICE, inner.data(), inner.size());
      }
      buf.push_back(TAG_END);
      return buf;
    }

    void deserialise(const std::vector<uint8_t> &buf,
                     HostStaticKey &host,
                     std::vector<KnownDevice> &known,
                     bool &have_host_static)
    {
      have_host_static = false;
      known.clear();
      if (buf.size() < sizeof(MAGIC) ||
          std::memcmp(buf.data(), MAGIC, sizeof(MAGIC)) != 0) {
        throw exc::EncodingException("THP store: bad magic header");
      }
      size_t off = sizeof(MAGIC);

      bool got_pub = false, got_priv = false;
      while (off < buf.size()) {
        uint8_t tag = buf[off++];
        if (tag == TAG_END) break;
        uint64_t len = 0;
        if (!read_varint(buf, off, len) || off + len > buf.size()) {
          throw exc::EncodingException("THP store: truncated record");
        }
        if (tag == TAG_HOST_STATIC_PUB && len == host.pub.size()) {
          std::memcpy(host.pub.data(), buf.data() + off, len);
          got_pub = true;
        } else if (tag == TAG_HOST_STATIC_PRIV && len == host.priv.size()) {
          std::memcpy(host.priv.data(), buf.data() + off, len);
          got_priv = true;
        } else if (tag == TAG_KNOWN_DEVICE) {
          KnownDevice kd;
          size_t inner_off = 0;
          while (inner_off < len) {
            uint8_t itag = buf[off + inner_off++];
            if (itag == KD_TAG_END) break;
            uint64_t ilen = 0;
            // varint over a sub-buffer view: emulate by passing the parent buf
            // with adjusted offset.
            size_t parent_off = off + inner_off;
            if (!read_varint(buf, parent_off, ilen)) {
              throw exc::EncodingException("THP store: truncated inner varint");
            }
            inner_off = parent_off - off;
            if (inner_off + ilen > len) {
              throw exc::EncodingException("THP store: inner record overflow");
            }
            const uint8_t *idata = buf.data() + off + inner_off;
            if (itag == KD_TAG_MASKED_STATIC && ilen == kd.trezor_masked_static_pubkey.size())
              std::memcpy(kd.trezor_masked_static_pubkey.data(), idata, ilen);
            else if (itag == KD_TAG_HOST_STATIC_PUB  && ilen == kd.host_static.pub.size())
              std::memcpy(kd.host_static.pub.data(),  idata, ilen);
            else if (itag == KD_TAG_HOST_STATIC_PRIV && ilen == kd.host_static.priv.size())
              std::memcpy(kd.host_static.priv.data(), idata, ilen);
            else if (itag == KD_TAG_PAIRING_CREDENTIAL)
              kd.pairing_credential.assign(idata, idata + ilen);
            // else: forward-compat, skip unknown tag
            inner_off += ilen;
          }
          known.push_back(std::move(kd));
        }
        // else: forward-compat, skip unknown tag
        off += len;
      }
      have_host_static = got_pub && got_priv;
    }

  } // anon

  std::string ThpStore::default_path(const std::string &wallet_dir)
  {
    // Place the store under <wallet_dir>/.trezor/thp_store.bin.  The
    // hidden subdirectory mirrors the existing convention used by the
    // wallet for caches.
    boost::filesystem::path p(wallet_dir);
    p /= ".trezor";
    p /= "thp_store.bin";
    return p.string();
  }

  void ThpStore::load_or_init(const std::string &path)
  {
    namespace fs = boost::filesystem;
    if (!fs::exists(path)) {
      // Empty store; caller will set_host_static() and save().
      m_host_static       = HostStaticKey{};
      m_known_devices.clear();
      m_have_host_static  = false;
      return;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
      throw exc::CommunicationException(std::string("THP store: cannot open ") + path);
    }
    std::stringstream ss;
    ss << f.rdbuf();
    auto s = ss.str();
    std::vector<uint8_t> buf(s.begin(), s.end());
    deserialise(buf, m_host_static, m_known_devices, m_have_host_static);
  }

  void ThpStore::save(const std::string &path) const
  {
    namespace fs = boost::filesystem;
    fs::path p(path);
    fs::create_directories(p.parent_path());
    fs::path tmp = p;
    tmp += ".tmp";

    auto buf = serialise(m_host_static, m_known_devices);

    {
      std::ofstream f(tmp.string(), std::ios::binary | std::ios::trunc);
      if (!f) {
        throw exc::CommunicationException(std::string("THP store: cannot write ") + tmp.string());
      }
      f.write(reinterpret_cast<const char *>(buf.data()), buf.size());
      f.flush();
      if (!f.good()) {
        throw exc::CommunicationException(std::string("THP store: write failed"));
      }
    }

#if !defined(_WIN32)
    // Tighten permissions to owner-rw before the atomic rename.
    if (chmod(tmp.string().c_str(), S_IRUSR | S_IWUSR) != 0) {
      // Don't fail if chmod is unsupported; just log via exception path
      // would be excessive. Continue.
    }
#endif

    boost::system::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec) {
      // On Windows rename across exists may need remove+rename.
      fs::remove(p, ec);
      fs::rename(tmp, p, ec);
      if (ec) {
        throw exc::CommunicationException(std::string("THP store: cannot rename to ") + path);
      }
    }
  }

  void ThpStore::upsert_known_device(const KnownDevice &kd)
  {
    for (auto &existing : m_known_devices) {
      if (std::memcmp(existing.trezor_masked_static_pubkey.data(),
                      kd.trezor_masked_static_pubkey.data(),
                      kd.trezor_masked_static_pubkey.size()) == 0) {
        existing = kd;
        return;
      }
    }
    m_known_devices.push_back(kd);
  }

}}}
