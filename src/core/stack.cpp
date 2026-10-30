/**
 * @file stack.cpp
 * @brief Stack-level integration implementation (sharded, multi-core parallel).
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/gso.h>
#include <xtcp/cc/cc.h>

#include <chrono>

namespace xtcp {
    namespace {
        constexpr UInt16 kIpv4 = 0x0800;
        constexpr UInt16 kIpv6 = 0x86DD;
        constexpr UInt64 kShardMask = 0x00FFFFFFFFFFFFFFull;

        // Tx batching (H4): the max number of packets collected into a fixed
        // stack array before a single TxBatch() call. 64 covers a full GSO
        // super-segment at typical MSS (a 64 KiB super-segment at MSS 1460 is
        // ~45 segments; a full 64 KiB at the 256-byte MSS floor would be 256,
        // so the batch also flushes at 64 - the array is a cap, not a
        // guarantee) and a full qdisc drain round without growing the stack.
        constexpr UInt32 kTxBatchMax = 64;

        // LOW (theoretical): next_id_ wraps at 2^56, so an id taken after a
        // wrap could collide with a live connection and overwrite it via the
        // unconditional conns_[id] = move(entry) at the allocation sites.
        // Reserve a free id by checking the shard's conns_ map (caller holds
        // shard->syncobj_, so the check-then-insert is race-free); retry on
        // collision, bail with 0 on exhaustion (unreachable at 2^56).
        template <typename ConnMap>
        inline UInt64 AllocConnId(std::atomic<UInt64>& next_id, UInt64 shard_bits,
                                  ConnMap& conns) noexcept {
            for (UInt32 attempt = 0; attempt < 64; ++attempt) {
                const UInt64 cand = shard_bits | (++next_id & kShardMask);
                if (0 != cand && conns.end() == conns.find(cand)) {
                    return cand;
                }
            }
            return 0;
        }

        inline UInt64 GetTickUs() noexcept {
            return static_cast<UInt64>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        }

        // Extracts the TCP flags from an IPv4/IPv6 packet (0 when the packet
        // is not a parseable TCP segment). EmitLocked uses this to keep SYN
        // (and RST) super-segments out of software GSO: segmenting a TFO SYN
        // that carries early data larger than the MSS would clone the SYN
        // flag (plus the TFO cookie / MSS / wscale options) onto every
        // fragment, which strict peers reject as a protocol violation (only
        // the first SYN is honored). Such a super-segment must go out whole
        // instead - the peer's IP layer fragments the oversize datagram.
        inline UInt16 TcpFlagsOf(const Byte* data, UInt32 len) noexcept {
            if (NULLPTR == data || 40 > len) {
                return 0;
            }
        const Byte version = static_cast<Byte>(data[0] >> 4);
            UInt32 ip_hdr_len = 0;
            if (4 == version) {
                core::Ip4Hdr ip;
                if (!core::ParseIp4(data, len, ip)) {
                    return 0;
                }
                ip_hdr_len = ip.payload_off;
            } else if (6 == version) {
                core::Ip6Hdr ip;
                if (!core::ParseIp6(data, len, ip)) {
                    return 0;
                }
                ip_hdr_len = ip.payload_off;
            } else {
                return 0;
            }
            if (len <= ip_hdr_len + 20) {
                return 0;
            }
            core::TcpHdr tcp;
            if (!core::ParseTcp(data + ip_hdr_len, len - ip_hdr_len, tcp)) {
                return 0;
            }
            return tcp.flags;
        }

#ifdef XTCP_CHECKSUM_VALIDATE
        // RFC 1071: fold two per-part checksums (each the ~sum of a range)
        // into the checksum of their concatenation (same helper as the
        // send-side tcp_fsm.cpp/gso.cpp).
        inline UInt16 ChecksumCombine(UInt16 a, UInt16 b) noexcept {
            UInt32 sum = (static_cast<UInt32>(~a) & 0xFFFF) + (static_cast<UInt32>(~b) & 0xFFFF);
            sum = (sum & 0xFFFF) + (sum >> 16);
            return static_cast<UInt16>(~sum & 0xFFFF);
        }

        // RFC 791: a valid IPv4 header recomputes to 0x0000 (the sender stores
        // the 16-bit one's complement of the header sum, so the header field
        // is part of the recomputation and an intact header folds to zero).
        bool VerifyIp4HeaderChecksum(const Byte* data, UInt32 hdr_len) noexcept {
            return 20 <= hdr_len && NULLPTR != data &&
                   0 == core::Checksum(data, hdr_len);
        }

        // RFC 793: TCP checksum = pseudo-header (IPv4 12B / IPv6 40B) + TCP
        // header (incl. checksum field) + payload, and must recompute to
        // 0x0000. src/dst are network-order endpoints parsed from the IP
        // header; tcp points at the TCP segment, tcp_len its full length.
        // Mirrors the send-side pseudo-header in tcp_fsm.cpp:321-382.
        bool VerifyTcpChecksum(const core::Endpoint& src, const core::Endpoint& dst,
                               const Byte* tcp, UInt32 tcp_len) noexcept {
            if (NULLPTR == tcp || 20 > tcp_len) {
                return false;
            }
            if (6 == src.family) {
                Byte pseudo[40];
                for (UInt32 i = 0; i < 4; ++i) {
                    const UInt32 s = src.addr[i];
                    const UInt32 d = dst.addr[i];
                    pseudo[i * 4]         = static_cast<Byte>(s >> 24);
                    pseudo[i * 4 + 1]     = static_cast<Byte>(s >> 16);
                    pseudo[i * 4 + 2]     = static_cast<Byte>(s >> 8);
                    pseudo[i * 4 + 3]     = static_cast<Byte>(s & 0xFF);
                    pseudo[16 + i * 4]    = static_cast<Byte>(d >> 24);
                    pseudo[16 + i * 4 + 1] = static_cast<Byte>(d >> 16);
                    pseudo[16 + i * 4 + 2] = static_cast<Byte>(d >> 8);
                    pseudo[16 + i * 4 + 3] = static_cast<Byte>(d & 0xFF);
                }
                pseudo[32] = static_cast<Byte>(tcp_len >> 24);
                pseudo[33] = static_cast<Byte>(tcp_len >> 16);
                pseudo[34] = static_cast<Byte>(tcp_len >> 8);
                pseudo[35] = static_cast<Byte>(tcp_len & 0xFF);
                pseudo[36] = 0;
                pseudo[37] = 0;
                pseudo[38] = 0;
                pseudo[39] = 6;  // TCP next-header
                return 0 == ChecksumCombine(core::Checksum(pseudo, sizeof(pseudo)),
                                            core::Checksum(tcp, tcp_len));
            }
            Byte pseudo[12];
            pseudo[0] = static_cast<Byte>(src.addr[0] >> 24);
            pseudo[1] = static_cast<Byte>(src.addr[0] >> 16);
            pseudo[2] = static_cast<Byte>(src.addr[0] >> 8);
            pseudo[3] = static_cast<Byte>(src.addr[0] & 0xFF);
            pseudo[4] = static_cast<Byte>(dst.addr[0] >> 24);
            pseudo[5] = static_cast<Byte>(dst.addr[0] >> 16);
            pseudo[6] = static_cast<Byte>(dst.addr[0] >> 8);
            pseudo[7] = static_cast<Byte>(dst.addr[0] & 0xFF);
            pseudo[8] = 0;
            pseudo[9] = 6;  // TCP protocol
            pseudo[10] = static_cast<Byte>(tcp_len >> 8);
            pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
            return 0 == ChecksumCombine(core::Checksum(pseudo, sizeof(pseudo)),
                                        core::Checksum(tcp, tcp_len));
        }
#endif

        // MurmurHash3 fmix64 finalizer: avalanche the 64-bit flow-key hash so
        // every input bit influences the low bits. The raw XOR/shift combine
        // below leaves the low 3 bits = saddr[0]&7 ^ dport&7 (the high-order
        // terms contribute nothing to the low bits), so a fixed client/server
        // churn (or any hash without good avalanche) collapses every flow onto
        // one shard. Applying the finalizer before % kShardCount spreads flows
        // evenly while keeping key -> shard fully deterministic.
        static inline UInt64 FinalMix(UInt64 h) noexcept {
            h ^= h >> 33;
            h *= 0xFF51AFD7ED558CCDull;
            h ^= h >> 33;
            h *= 0xC4CEB9FE1A85EC53ull;
            h ^= h >> 33;
            return h;
        }

        // RFC 793: RST for a SYN to a closed port (connection refused), with
        // ACK = SYN seq+1 so the client accepts it in SYN-SENT.
        void SendClosedPortRst(ndi::Backend* backend, std::recursive_mutex& tx_lock,
                               const core::Endpoint& dst,
                               const core::Endpoint& src, UInt32 syn_seq) noexcept {
            if (NULLPTR == backend || (4 != dst.family && 6 != dst.family)) {
                return;
            }
            const bool v6 = (6 == dst.family);
            Byte pkt[80];
            std::memset(pkt, 0, sizeof(pkt));
            const UInt32 ip_hdr = v6 ? 40u : 20u;
            Byte* t = pkt + ip_hdr;
            if (v6) {
                // RFC 8200: version 6, payload length 20 (TCP only), next
                // header 6 (TCP), hop limit 64, then 16-byte src/dst.
                pkt[0] = 0x60;
                pkt[4] = 0; pkt[5] = 20;
                pkt[6] = 6;
                pkt[7] = 64;
                for (UInt32 w = 0; w < 4; ++w) {
                    pkt[8 + w * 4] = static_cast<Byte>(dst.addr[w] >> 24);
                    pkt[9 + w * 4] = static_cast<Byte>(dst.addr[w] >> 16);
                    pkt[10 + w * 4] = static_cast<Byte>(dst.addr[w] >> 8);
                    pkt[11 + w * 4] = static_cast<Byte>(dst.addr[w] & 0xFF);
                    pkt[24 + w * 4] = static_cast<Byte>(src.addr[w] >> 24);
                    pkt[25 + w * 4] = static_cast<Byte>(src.addr[w] >> 16);
                    pkt[26 + w * 4] = static_cast<Byte>(src.addr[w] >> 8);
                    pkt[27 + w * 4] = static_cast<Byte>(src.addr[w] & 0xFF);
                }
            } else {
                pkt[0] = 0x45;
                pkt[2] = 0; pkt[3] = 40;
                pkt[8] = 64;
                pkt[9] = 6;
                pkt[12] = static_cast<Byte>(dst.addr[0] >> 24);
                pkt[13] = static_cast<Byte>(dst.addr[0] >> 16);
                pkt[14] = static_cast<Byte>(dst.addr[0] >> 8);
                pkt[15] = static_cast<Byte>(dst.addr[0] & 0xFF);
                pkt[16] = static_cast<Byte>(src.addr[0] >> 24);
                pkt[17] = static_cast<Byte>(src.addr[0] >> 16);
                pkt[18] = static_cast<Byte>(src.addr[0] >> 8);
                pkt[19] = static_cast<Byte>(src.addr[0] & 0xFF);
            }
            t[0] = static_cast<Byte>(dst.port >> 8);
            t[1] = static_cast<Byte>(dst.port & 0xFF);
            t[2] = static_cast<Byte>(src.port >> 8);
            t[3] = static_cast<Byte>(src.port & 0xFF);
            const UInt32 ack = syn_seq + 1;
            t[8] = static_cast<Byte>(ack >> 24);
            t[9] = static_cast<Byte>(ack >> 16);
            t[10] = static_cast<Byte>(ack >> 8);
            t[11] = static_cast<Byte>(ack & 0xFF);
            t[12] = 0x50;
            t[13] = 0x14;  // RST | ACK

            if (!v6) {
                // RFC 791: IPv4 header checksum (checksum field is still 0).
                const UInt16 ip_sum = core::Checksum(pkt, 20);
                pkt[10] = static_cast<Byte>(ip_sum >> 8);
                pkt[11] = static_cast<Byte>(ip_sum & 0xFF);
            }

            // RFC 793: TCP checksum with the IPv4/IPv6 pseudo header. The RST
            // is sent from the closed local port (dst, the SYN's destination)
            // to the client (src, the SYN's source); pseudo header src IP =
            // dst, dst IP = src (mirror of tcp_fsm.cpp:357-382). No payload,
            // so the 20-byte TCP header checksummed with the pseudo header
            // (both checksum fields still 0).
            Byte pseudo[64];
            std::memset(pseudo, 0, sizeof(pseudo));
            if (v6) {
                // RFC 8200 pseudo header: src(16) + dst(16) + length(4) +
                // zero(3) + next(1) = 40 bytes, then the TCP segment.
                for (UInt32 w = 0; w < 4; ++w) {
                    pseudo[w * 4] = static_cast<Byte>(dst.addr[w] >> 24);
                    pseudo[w * 4 + 1] = static_cast<Byte>(dst.addr[w] >> 16);
                    pseudo[w * 4 + 2] = static_cast<Byte>(dst.addr[w] >> 8);
                    pseudo[w * 4 + 3] = static_cast<Byte>(dst.addr[w] & 0xFF);
                    pseudo[16 + w * 4] = static_cast<Byte>(src.addr[w] >> 24);
                    pseudo[17 + w * 4] = static_cast<Byte>(src.addr[w] >> 16);
                    pseudo[18 + w * 4] = static_cast<Byte>(src.addr[w] >> 8);
                    pseudo[19 + w * 4] = static_cast<Byte>(src.addr[w] & 0xFF);
                }
                pseudo[32] = 0; pseudo[33] = 0; pseudo[34] = 0; pseudo[35] = 20;
                pseudo[39] = 6;  // next header: TCP
                std::memcpy(pseudo + 40, t, 20);
            } else {
                pseudo[0] = static_cast<Byte>(dst.addr[0] >> 24);
                pseudo[1] = static_cast<Byte>(dst.addr[0] >> 16);
                pseudo[2] = static_cast<Byte>(dst.addr[0] >> 8);
                pseudo[3] = static_cast<Byte>(dst.addr[0] & 0xFF);
                pseudo[4] = static_cast<Byte>(src.addr[0] >> 24);
                pseudo[5] = static_cast<Byte>(src.addr[0] >> 16);
                pseudo[6] = static_cast<Byte>(src.addr[0] >> 8);
                pseudo[7] = static_cast<Byte>(src.addr[0] & 0xFF);
                pseudo[8] = 0x00;
                pseudo[9] = 6;  // TCP
                pseudo[10] = 0x00;
                pseudo[11] = 20;  // TCP segment length: 20-byte header, no payload
                std::memcpy(pseudo + 12, t, 20);
            }
            const UInt16 tcp_sum = core::Checksum(pseudo, v6 ? 60u : 32u);
            t[16] = static_cast<Byte>(tcp_sum >> 8);
            t[17] = static_cast<Byte>(tcp_sum & 0xFF);

            ndi::Packet out;
            out.data = pkt;
            out.len = v6 ? 60u : 40u;
            out.eth_type = v6 ? kIpv6 : kIpv4;
            // Same backend serialization as every other emit site: this RST
            // is built without a connection, but it still shares the
            // backend's transmit queue with the data path. Sending it
            // unlocked races Tx() against the shards' emissions (the same
            // corruption class as the data path).
            {
                std::lock_guard<std::recursive_mutex> tx_scope(tx_lock);
                backend->Tx(std::move(out));  // best-effort: a rejected RST is harmless (the SYN retransmits)
            }
        }

        // Listener address comparison (IPv4: addr[0]; IPv6: addr[0..3]).
        inline bool AddrEqual(const core::Endpoint& a, const core::Endpoint& b) noexcept {
            const UInt32 words = (6 == a.family) ? 4 : 1;
            for (UInt32 i = 0; i < words; ++i) {
                if (a.addr[i] != b.addr[i]) {
                    return false;
                }
            }
            return true;
        }

        // An all-zero address is a wildcard listener: it matches any source
        // address (Linux INADDR_ANY / in6addr_any semantics).
        inline bool AddrIsWildcard(const core::Endpoint& ep) noexcept {
            const UInt32 words = (6 == ep.family) ? 4 : 1;
            for (UInt32 i = 0; i < words; ++i) {
                if (0 != ep.addr[i]) {
                    return false;
                }
            }
            return true;
        }

        // A listener accepts a SYN destined to `local` iff same family + port
        // and the listener's address is a wildcard or exactly equals local's
        // address. A listener bound to a specific address never answers SYNs
        // for other addresses on the same port.
        inline bool ListenerMatches(const core::Endpoint& listener,
                                    const core::Endpoint& local) noexcept {
            if (listener.family != local.family || listener.port != local.port) {
                return false;
            }
            return AddrIsWildcard(listener) || AddrEqual(listener, local);
        }
    }

    XtcpStack::XtcpStack(ndi::Backend* backend) noexcept
        : backend_(backend), ipfrag_(30000000, 4096) {
        cc::RegisterBuiltinCc();  // KCC/BBRv1/CUBIC selectable via SetCongestionControl
        qdisc::RegisterFqDefault();  // default qdisc algorithm: FQ (sch_fq semantics)
        // Uniform nothrow convention. The shard array is small (8 Shards);
        // an allocation failure here is practically unreachable and
        // UNSUPPORTED: ShardOf keeps the conn-id hot path branch-free and
        // would return a null-derived pointer (the destructor null-checks as
        // belt-and-suspenders, but callers dereference unconditionally).
        shards_.reset(new (std::nothrow) Shard[kShardCount]);
        if (NULLPTR != shards_.get()) {
            for (UInt32 i = 0; i < kShardCount; ++i) {
                shards_[i].FlowInit(256);  // flat flow-route table (perf #3)
            }
        }
        if (NULLPTR != backend_) {
            caps_ = backend_->Caps();  // Caps() is constant for the backend's lifetime; snapshot once
            backend_->SetRxHandler([this](ndi::Packet&& packet) noexcept {
                if (NULLPTR == packet.data || 0 == packet.len) {
                    return;
                }
                if (!packet.owned.IsEmpty()) {
                    // Zero-copy rx: the backend already provided a pool
                    // buffer; adopt it without copying. Guard: a claimed
                    // packet.len beyond the buffer capacity would make every
                    // consumer read out of bounds (Bug 1). Drop such packets.
                    if (packet.len > packet.owned.Capacity()) {
                        return;
                    }
                    packet.owned.SetLen(packet.len);
                    OnPacket(std::move(packet.owned));
                    return;
                }
                // Fallback: copy the borrowed buffer into a pool block.
                buf::BufRef buf = buf::BufRef::Acquire(packet.len);
                if (!buf.IsEmpty()) {
                    std::memcpy(buf.Data(), packet.data, packet.len);
                    buf.SetLen(packet.len);
                    OnPacket(std::move(buf));
                }
            });
        }
    }

        XtcpStack::~XtcpStack() noexcept {
            // MIMT flow lifetime (BUG-3): flows delivered to the app may
            // outlive this stack (the app holds shared_ptrs). Their write
            // sinks capture [this, id] and dereference the shards - so
            // neutralize every flow BEFORE the shards are destroyed: Close()
            // completes all pending async ops with kClosed (1:1 pairing) and
            // disables the sink (write_pending_ cleared), making any late
            // Dispatch()/AsyncWrite() a safe no-op/kClosed instead of a
            // use-after-free.
            for (UInt32 i = 0; i < kShardCount; ++i) {
                Shard* s = &shards_[i];
                if (NULLPTR == s) {
                    continue;
                }
                std::lock_guard<std::recursive_mutex> scope(s->syncobj_);
                for (auto& kv : s->mimt_flows_) {
                    if (kv.second) {
                        kv.second->Close();
                    }
                }
                s->mimt_flows_.clear();
            }
        }

    XtcpStack::Shard* XtcpStack::ShardOf(const core::FlowKey& key) noexcept {
        // Hash the FULL flow key (family + all 4 address words + ports) via
        // the same HashFlowKey that backs flow_slots_/FlowKeyHash, then
        // avalanche. The old XOR combined only saddr[0]/daddr[0]/ports, so
        // IPv6 flows under a common /32 prefix (words 1-3 differ) all landed
        // on the same shard. Flow placement (Connect) and rx lookup both use
        // this function, so key -> shard stays consistent; the conn-id shard
        // byte is derived from this result at allocation time.
        const UInt64 v = FinalMix(core::scheduler_hash::HashFlowKey(key));
        return shards_.get() + (static_cast<UInt32>(v) % kShardCount);
    }

    XtcpStack::Shard* XtcpStack::ShardOf(UInt64 conn_id) const noexcept {
        // Bug G: a garbage conn_id (e.g. a caller passing an unverified value)
        // could encode a shard index beyond kShardCount and index shards_ out
        // of bounds. Modulo bounds the index; conns_.find(id) then simply
        // misses for such an id, which every caller already handles.
        const UInt32 idx = static_cast<UInt32>(conn_id >> 56) % kShardCount;
        return shards_.get() + idx;
    }

    core::FlowKey XtcpStack::KeyOf(const core::Endpoint& local, const core::Endpoint& remote) const noexcept {
        core::FlowKey key;
        key.addr_family = local.family;
        for (UInt32 i = 0; i < 4; ++i) {
            key.saddr[i] = local.addr[i];
            key.daddr[i] = remote.addr[i];
        }
        key.sport = local.port;
        key.dport = remote.port;
        return key;
    }

        bool XtcpStack::LookupListenerMd5Key(const core::Endpoint& dst, Byte* out_key, UInt32* out_len) const noexcept {
            if (NULLPTR == out_key || NULLPTR == out_len) {
                return false;
            }
            *out_len = 0;
            const UInt64 h = EndpointKey(dst);
            auto it = listener_md5_.find(h);
            if (it == listener_md5_.end()) {
                // Wildcard fallback: a 0.0.0.0 / :: listener armed with an MD5
                // key must enforce it for SYNs to any specific destination
                // (mirror of ListenerMatches). Without this, an MD5-armed
                // wildcard listener silently enforced nothing.
                for (const core::Endpoint& ep : listeners_) {
                    if (ep.family != dst.family || ep.port != dst.port || !AddrIsWildcard(ep)) {
                        continue;
                    }
                    const UInt64 wh = EndpointKey(ep);
                    auto wit = listener_md5_.find(wh);
                    if (wit != listener_md5_.end() && 0 < listener_md5_len_.at(wh)) {
                        const UInt32 n = listener_md5_len_.at(wh);
                        std::memcpy(out_key, wit->second.data(), n);
                        *out_len = n;
                        return true;
                    }
                }
                return false;
            }
            const UInt32 n = listener_md5_len_.at(h);
            if (0 == n) {
                return false;  // soft-removed (len 0)
            }
            std::memcpy(out_key, it->second.data(), n);
            *out_len = n;
            return true;
        }

        bool XtcpStack::IsListening(const core::Endpoint& local) const noexcept {
        std::lock_guard<std::recursive_mutex> scope(syncobj_);
        for (const core::Endpoint& listener : listeners_) {
            if (ListenerMatches(listener, local)) {
                return true;
            }
        }
        return false;
    }

    void XtcpStack::Emit(UInt64 conn_id, ConnEntry* conn, buf::BufRef&& packet) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        EmitLocked(conn_id, conn, std::move(packet));
    }

    void XtcpStack::EmitLocked(UInt64 conn_id, ConnEntry* conn, buf::BufRef&& packet) noexcept {
        // Caller MUST already hold the shard lock for ShardOf(conn_id). All
        // sink call sites (stack.cpp:1158/1281/2058/2282) fire from TcpConn
        // methods invoked while that lock is held (Send/OnPacket/PollAckTimers
        // hold it across the call). Skipping the recursive re-lock saves 2
        // atomic RMWs per segment on the tx hot path.
        Shard* shard = ShardOf(conn_id);  // the lock is already held by the caller
        if (NULLPTR == backend_ || packet.IsEmpty()) {
            return;
        }
        // Modulo bounds the index against kShardCount (defense-in-depth: a
        // garbage conn_id must never index tx_count_ out of bounds - mirror
        // the ShardOf(UInt64) guard above). conns_.find() misses for such an
        // id anyway, so the bounded index is harmless on the hot path.
        // Per-packet emit counting (Bug 2): a GSO super-segment splits into N
        // MSS-sized packets, so the count must move once per actual packet on
        // the wire - at each emission point (TSO passthrough, GSO batch,
        // SendOne) - not once per super-segment here. The old single fetch_add
        // under-counted a GSO'd send by N-1.
        std::atomic<UInt64>& tx_cnt = tx_count_[(static_cast<UInt32>(conn_id >> 56)) % kShardCount];
        if (NULLPTR == conn) {
            return;
        }
        const UInt16 eth_type = (6 == (packet.Data()[0] >> 4)) ? kIpv6 : kIpv4;
        const UInt16 mss = (NULLPTR != conn->conn) ? conn->conn->PeerMss() : 1460;
        // Defense in depth: a signed connection is never segmented at the tx
        // boundary (GSO rebuilds headers and would strip the MD5 option).
        // The send path already caps signed payloads, but an oversized signed
        // segment must go out whole (IP fragmentation) rather than broken.
        const bool signed_conn = (NULLPTR != conn->conn) && conn->conn->Md5Enabled();
        // `conn` is the ConnEntry captured by the sink lambda: the sink only
        // fires from a method on a live TcpConn, and an entry is reclaimed
        // only under this shard's lock (which Emit holds), so the pointer is
        // always valid here. PeerMss()/Md5Enabled() stay live reads (PMTUD /
        // SetMd5Key change them). Caps() is constant - cached in caps_.
        const ndi::BackendCaps caps = caps_;
        if (0 != (caps & ndi::kCapTsoTx) && !signed_conn && NULLPTR == tx_qdisc_) {
            // TSO passthrough: the backend segments (or the NIC does).
            // Signed connections must never be NIC-segmented: the hardware
            // splits the super-segment without re-inserting the MD5 option,
            // breaking the peer's signature verification. They skip TSO and
            // fall through to SendOne (IP fragmentation preserves the whole
            // signed segment).
            // With a tx qdisc mounted, TSO passthrough is DISABLED: the
            // super-segment would reach the backend without ever passing the
            // qdisc (no pacing, no fairness - the qdisc would be dead
            // weight). Such packets fall through to software GSO + SendOne,
            // which enqueue per segment (audit M1).
            ndi::Packet out;
            out.data = packet.Data();
            out.len = packet.Len();
            out.eth_type = eth_type;
            out.owned = std::move(packet);
            tx_cnt.fetch_add(1, std::memory_order_relaxed);  // TSO: one packet to the backend (NIC segments)
            EmitOrRetry(*shard, std::move(out));
            return;
        }
        const UInt32 gso_threshold = static_cast<UInt32>(mss) + ((kIpv6 == eth_type) ? 60 : 40);
        // Never GSO a SYN (or RST) super-segment: segmentation would clone
        // the SYN flag (plus the TFO cookie / MSS / wscale options) onto
        // every fragment - a protocol violation, strict peers only honor the
        // first SYN. A TFO SYN carrying early data larger than the MSS must
        // go out whole; the peer's IP layer fragments the oversize datagram.
        if (packet.Len() > gso_threshold && !signed_conn &&
            0 == (TcpFlagsOf(packet.Data(), packet.Len()) & static_cast<UInt16>(core::kFlagSyn | core::kFlagRst))) {
            // Software GSO at the tx boundary: segment the super-segment
            // into MSS-sized packets (the peer negotiated this MSS).
            std::vector<core::GsoSeg> segs;
            if (core::GsoSegment(packet, mss, segs) && !segs.empty()) {
                // Tx batching (H4): without a tx qdisc every segment goes
                // straight to the backend, so collect them into a fixed stack
                // array and emit one TxBatch. With a qdisc each segment must
                // still go through SendOne (enqueue + pacing drain).
                const bool has_qdisc = (NULLPTR != tx_qdisc_ && NULLPTR != tx_qdisc_->ops &&
                                        NULLPTR != tx_qdisc_->ops->enqueue && NULLPTR != tx_qdisc_->ops->dequeue);
                ndi::Packet batch[kTxBatchMax];
                UInt32 batch_count = 0;
                auto FlushBatch = [&]() noexcept {
                    if (0 < batch_count) {
                        UInt32 accepted = 0;
                        {
                            std::lock_guard<std::recursive_mutex> scope(backend_tx_mutex_);
                            accepted = backend_->TxBatch(batch, batch_count);
                        }
                    // GSO segments belong to THIS connection: defer them on
                    // its own shard's retry queue (never shard 0) so the
                    // retry drain keeps every connection's wire order.
                    RetryBatch(*shard, batch, accepted, batch_count);
                        batch_count = 0;
                    }
                };
                for (core::GsoSeg& seg : segs) {
                    UInt32 total = 0;
                    for (const core::GsoIov& iov : seg.iovs) {
                        total += iov.len;
                    }
                    buf::BufRef buf = buf::BufRef::Acquire(total);
                    if (buf.IsEmpty()) {
                        // Buffer pool exhausted mid-segmentation. Never
                        // silently drop the rest of the super-segment
                        // (SendOne's own fallback at the bottom): bail out
                        // and send the whole remaining packet raw - the
                        // peer's IP layer fragments it. Segments already
                        // emitted are harmless duplicates the peer drops.
                        FlushBatch();
                        SendOne(conn_id, conn, eth_type, std::move(packet));
                        return;
                    }
                    UInt32 off = 0;
                    for (const core::GsoIov& iov : seg.iovs) {
                        std::memcpy(buf.Data() + off, iov.data, iov.len);
                        off += iov.len;
                    }
                    buf.SetLen(total);
                    if (has_qdisc) {
                        SendOne(conn_id, conn, eth_type, std::move(buf));
                    } else {
                        // Index invariant (induction over segs): entering
                        // every iteration 0 <= batch_count < kTxBatchMax -
                        // it starts at 0 and each iteration ends either
                        // below the cap or reset to 0 by FlushBatch. MSVC
                        // /analyze cannot track the counter through the
                        // FlushBatch lambda and flags batch[batch_count]
                        // as C6385; suppress that false positive here.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 6385)
#endif
                        ndi::Packet& out = batch[batch_count];
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
                        out.data = buf.Data();
                        out.len = buf.Len();
                        out.eth_type = eth_type;
                        out.owned = std::move(buf);
                        ++batch_count;
                        tx_cnt.fetch_add(1, std::memory_order_relaxed);  // one GSO segment on the wire
                        if (kTxBatchMax == batch_count) {
                            FlushBatch();
                        }
                    }
                }
                FlushBatch();
                return;
            }
            // GSO failed (malformed): fall through to a raw tx; the peer's
            // IP layer fragments oversized datagrams.
        }
        SendOne(conn_id, conn, eth_type, std::move(packet));
    }

    void XtcpStack::SendOne(UInt64 conn_id, ConnEntry* conn, UInt16 eth_type, buf::BufRef&& packet) noexcept {
        Shard* shard = ShardOf(conn_id);  // the caller holds the shard lock
        std::atomic<UInt64>& tx_cnt = tx_count_[(static_cast<UInt32>(conn_id >> 56)) % kShardCount];
        // Optional tx qdisc: enqueue, then drain whatever the pacing clock
        // allows right now (the rest waits for PollAckTimers).
        if (NULLPTR != tx_qdisc_ && NULLPTR != tx_qdisc_->ops &&
            NULLPTR != tx_qdisc_->ops->enqueue && NULLPTR != tx_qdisc_->ops->dequeue) {
            // CC pacing -> qdisc per-flow rate bridge (qdisc audit M2/M5):
            // the FQ's internal pacing gate only engages when the flow has a
            // rate; without this the stack-mounted qdisc never paced (rate 0
            // = immediate drain, the M5 dead-feature finding). Propagate the
            // connection's pacing_rate ONLY when the flow has no
            // user-configured rate (get_pacing_rate == 0): a manually-set
            // rate (e.g. a 1 Mbps test gate) must never be clobbered by the
            // Reno ACK-clock value, whose µs-scale srtt on in-memory
            // backends yields a Gbps+ rate that defeats the gate.
            // Perf: the CC rate only changes per RTT, but the bridge used to
            // take the qdisc mutex (get_pacing_rate + maybe set_pacing_rate)
            // on EVERY segment - measured 35% throughput loss with a mounted
            // qdisc. Cache the propagated rate per connection (ConnEntry,
            // under the shard lock) and skip both qdisc calls while the rate
            // is unchanged (steady state).
            if (NULLPTR != tx_qdisc_->ops->set_pacing_rate && NULLPTR != conn &&
                NULLPTR != conn->conn) {
                const UInt64 conn_rate = conn->conn->PacingRate();
                if (conn->qdisc_cached != tx_qdisc_ || conn->qdisc_rate_cached != conn_rate) {
                    const UInt64 flow_rate = (NULLPTR != tx_qdisc_->ops->get_pacing_rate)
                        ? tx_qdisc_->ops->get_pacing_rate(tx_qdisc_, conn_id)
                        : 0;
                    if (0 == flow_rate && 0 < conn_rate) {
                        tx_qdisc_->ops->set_pacing_rate(tx_qdisc_, conn_id, conn_rate);
                    }
                    conn->qdisc_rate_cached = conn_rate;
                    conn->qdisc_cached = tx_qdisc_;
                }
            }
            // Perf fast path: enqueue + immediate drain under ONE lock when
            // the qdisc was empty and the flow is not pacing-gated (measured
            // 35-40% throughput loss with a mounted qdisc from the old
            // enqueue -> DrainTxQdisc round-trip: two mutexes, GetTickUs and
            // a TxBatch per segment). enqueue_drain returns the packet for
            // direct emission; an empty result means it was queued (paced or
            // behind backlog) - run the normal drain loop then.
            if (NULLPTR != tx_qdisc_->ops->enqueue_drain) {
                core::TimePoint next = 0;
                buf::BufRef fast;
                const int rc = tx_qdisc_->ops->enqueue_drain(
                    tx_qdisc_, conn_id, std::move(packet), GetTickUs(), &fast, &next);
                if (0 != rc) {
                    return;  // dropped (queue limit): tail-drop semantics
                }
                if (!fast.IsEmpty()) {
                    ndi::Packet out;
                    out.data = fast.Data();
                    out.len = fast.Len();
                    out.eth_type = eth_type;
                    out.owned = std::move(fast);
                    EmitOrRetry(*shard, std::move(out));
                    tx_cnt.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                if (0 != next) {
                    qdisc_next_pacing_.store(next, std::memory_order_relaxed);
                }
                DrainTxQdisc(GetTickUs());
                tx_cnt.fetch_add(1, std::memory_order_relaxed);  // packet handed to the qdisc (drained or paced)
                return;
            }
            if (0 == tx_qdisc_->ops->enqueue(tx_qdisc_, conn_id, std::move(packet))) {
                DrainTxQdisc(GetTickUs());
                tx_cnt.fetch_add(1, std::memory_order_relaxed);  // packet handed to the qdisc (drained or paced)
                return;
            }
            // Enqueue rejected (flow/global queue full): TAIL-DROP (Linux
            // sch_fq semantics). The segment is a clone - SendSegment stored
            // its twin in retrans_queue_ before emitting (the TX path is
            // Clone-balanced: queue + backend), so the RTO retransmits it
            // once the queue drains; ACKs are regenerated by the peer's
            // retransmissions. NEVER bypass the qdisc here: the qdisc may
            // still hold OLDER segments of this very flow, and a direct
            // backend tx would put a NEWER segment on the wire ahead of
            // them - the peer sees out-of-order data, floods dup-ACKs and
            // spuriously triggers fast retransmission (audit C1).
            return;
        }
        tx_cnt.fetch_add(1, std::memory_order_relaxed);  // direct backend tx
        ndi::Packet out;
        out.data = packet.Data();
        out.len = packet.Len();
        out.eth_type = eth_type;
        // Zero-copy tx: hand the pool buffer's ownership to the backend so it
        // can hold (and later write) the packet without copying.
        out.owned = std::move(packet);
        EmitOrRetry(*shard, std::move(out));
    }

        // DMA/PCIe TX backpressure: when the backend's ring is full (Tx
        // returns false), the packet is NOT dropped - it is deferred on the
        // shard's retry queue (ownership retained) and drained by the next
        // PollAckTimers sweep. Borrowed packets are copied before deferring
        // (the source buffer dies when this call returns).
        // MPSC push: the retry chain head is atomic - this
        // path holds the shard lock, but the same chain can be pushed by a
        // foreign shard's drain without that lock, so the push must be
        // lock-free (a deque push would race the sweep's locked pop).
        void XtcpStack::EmitOrRetry(Shard& shard, ndi::Packet&& out) noexcept {
            // Serialized: see backend_tx_mutex_ (a backend's transmit queue
            // tolerates one writer; shards emit concurrently otherwise).
            bool accepted = false;
            {
                std::lock_guard<std::recursive_mutex> scope(backend_tx_mutex_);
                accepted = backend_->Tx(std::move(out));
            }
            if (accepted) {
                return;
            }
            buf::BufRef ref;
            if (!out.owned.IsEmpty()) {
                ref = std::move(out.owned);
            } else if (NULLPTR != out.data && 0 < out.len) {
                ref = buf::BufRef::Acquire(out.len);
                if (!ref.IsEmpty()) {
                    std::memcpy(ref.Data(), out.data, out.len);
                    ref.SetLen(out.len);
                }
            }
            if (!ref.IsEmpty() &&
                shard.tx_retry_count_.fetch_add(1, std::memory_order_relaxed) <
                    Shard::kTxRetryCap) {
                Shard::TxRetry* node = new (std::nothrow) Shard::TxRetry();
                if (NULLPTR != node) {
                    node->ref = std::move(ref);
                    node->eth_type = out.eth_type;
                    node->next = shard.tx_retry_head_.load(std::memory_order_relaxed);
                    while (!shard.tx_retry_head_.compare_exchange_weak(
                               node->next, node, std::memory_order_release,
                               std::memory_order_relaxed)) {
                    }
                } else {
                    // OOM: roll the reservation back; the pool-exhaustion
                    // drop above already documented the recovery net.
                    shard.tx_retry_count_.fetch_sub(1, std::memory_order_relaxed);
                }
            }
            MarkSweep(shard);  // the sweep drains the retry queue
        }

        // DMA backpressure for the batch path: re-queue every packet in
        // [from, count) that TxBatch did not accept. The retry chain is
        // MPSC: this can be reached for a FOREIGN shard while
        // holding OUR shard's lock, so the push must be lock-free - a
        // std::deque push here raced the sweep's locked pop (UB).
        void XtcpStack::RetryBatch(Shard& shard, ndi::Packet* packets, UInt32 from, UInt32 count) noexcept {
            for (UInt32 i = from; i < count; ++i) {
                ndi::Packet& p = packets[i];
                buf::BufRef ref;
                if (!p.owned.IsEmpty()) {
                    ref = std::move(p.owned);
                } else if (NULLPTR != p.data && 0 < p.len) {
                    ref = buf::BufRef::Acquire(p.len);
                    if (!ref.IsEmpty()) {
                        std::memcpy(ref.Data(), p.data, p.len);
                        ref.SetLen(p.len);
                    }
                }
                if (ref.IsEmpty() ||
                    shard.tx_retry_count_.fetch_add(1, std::memory_order_relaxed) >=
                        Shard::kTxRetryCap) {
                    if (!ref.IsEmpty()) {
                        // Cap hit: roll the reservation back and drop; the
                        // TCP RTO re-covers the bytes (same net as below).
                        shard.tx_retry_count_.fetch_sub(1, std::memory_order_relaxed);
                    }
                    continue;  // pool exhaustion: drop (TCP RTO re-covers the bytes)
                }
                Shard::TxRetry* node = new (std::nothrow) Shard::TxRetry();
                if (NULLPTR == node) {
                    shard.tx_retry_count_.fetch_sub(1, std::memory_order_relaxed);
                    continue;  // OOM: same recovery net as above
                }
                node->ref = std::move(ref);
                node->eth_type = p.eth_type;
                node->next = shard.tx_retry_head_.load(std::memory_order_relaxed);
                while (!shard.tx_retry_head_.compare_exchange_weak(
                           node->next, node, std::memory_order_release,
                           std::memory_order_relaxed)) {
                }
            }
            if (from < count) {
                MarkSweep(shard);
            }
        }

    void XtcpStack::DrainTxQdisc(core::TimePoint now) noexcept {        if (NULLPTR == tx_qdisc_ || NULLPTR == tx_qdisc_->ops ||
            NULLPTR == tx_qdisc_->ops->dequeue || NULLPTR == backend_) {
            return;
        }
        qdisc_next_pacing_.store(0, std::memory_order_relaxed);
        // Tx batching (H4): collect up to kTxBatchMax dequeued packets into a
        // fixed stack array and emit one TxBatch per group. next_pacing
        // storage timing is unchanged: it is only written when dequeue
        // reports the queue empty, exactly as before.
        ndi::Packet batch[kTxBatchMax];
        UInt32 batch_count = 0;
        for (;;) {
            core::TimePoint next = 0;
            buf::BufRef packet = tx_qdisc_->ops->dequeue(tx_qdisc_, now, &next);
            if (packet.IsEmpty()) {
                if (0 < batch_count) {
                    UInt32 accepted = 0;
                    {
                        std::lock_guard<std::recursive_mutex> scope(backend_tx_mutex_);
                        accepted = backend_->TxBatch(batch, batch_count);
                    }
                    RetryBatchSharded(batch, accepted, batch_count);
                    batch_count = 0;
                }
                if (0 != next) {
                    qdisc_next_pacing_.store(next, std::memory_order_relaxed);
                } else if (NULLPTR != tx_qdisc_->ops->has_backlog &&
                           tx_qdisc_->ops->has_backlog(tx_qdisc_)) {
                    // Safety net: the qdisc still holds packets but reported no
                    // pacing clock, so no algorithm's missed next_pacing can
                    // stall the qdisc forever. Retry in 1 ms.
                    qdisc_next_pacing_.store(now + 1000, std::memory_order_relaxed);
                }
                return;
            }
            ndi::Packet& out = batch[batch_count];
            out.data = packet.Data();
            out.len = packet.Len();
            out.eth_type = (6 == (packet.Data()[0] >> 4)) ? kIpv6 : kIpv4;
            out.owned = std::move(packet);
            ++batch_count;
            if (kTxBatchMax == batch_count) {
                UInt32 accepted = 0;
                {
                    std::lock_guard<std::recursive_mutex> scope(backend_tx_mutex_);
                    accepted = backend_->TxBatch(batch, batch_count);
                }
                RetryBatchSharded(batch, accepted, batch_count);
                batch_count = 0;
            }
        }
    }

    // DMA backpressure for qdisc-drained batches: TxBatch's acceptance
    // signal carries no flow identity, so attribute each rejected packet to
    // its connection's shard by its 5-tuple (dequeue returns bare packets).
    // Deferring every rejected packet to shard 0 would put a connection's
    // deferred segments on a FOREIGN shard's retry queue - drained at a
    // different time than the connection's own shard - reordering the
    // connection's segments on the wire (the peer sees transient dup-ACKs).
    void XtcpStack::RetryBatchSharded(ndi::Packet* packets, UInt32 from, UInt32 count) noexcept {
        for (UInt32 i = from; i < count; ++i) {
            Shard* s = ShardOfPacket(packets[i]);
            if (NULLPTR == s) {
                s = shards_.get();  // unparseable (never: stack-emitted): shard 0
            }
            RetryBatch(*s, packets, i, i + 1);
        }
    }

    XtcpStack::Shard* XtcpStack::ShardOfPacket(const ndi::Packet& p) noexcept {
        core::Endpoint src, dst;
        UInt32 tcp_off = 0;
        if (4 == (p.data[0] >> 4)) {
            core::Ip4Hdr ip4;
            if (!core::ParseIp4(p.data, p.len, ip4) || 6 != ip4.proto) {
                return NULLPTR;
            }
            src.family = 4;
            src.addr[0] = ip4.src;
            dst.family = 4;
            dst.addr[0] = ip4.dst;
            tcp_off = ip4.payload_off;
        } else if (6 == (p.data[0] >> 4)) {
            core::Ip6Hdr ip6;
            if (!core::ParseIp6(p.data, p.len, ip6) || 6 != ip6.proto) {
                return NULLPTR;
            }
            src.family = 6;
            dst.family = 6;
            for (UInt32 i = 0; i < 4; ++i) {
                src.addr[i] = ip6.src[i];
                dst.addr[i] = ip6.dst[i];
            }
            tcp_off = ip6.payload_off;
        } else {
            return NULLPTR;
        }
        if (tcp_off + 20 > p.len) {
            return NULLPTR;
        }
        const Byte* t = p.data + tcp_off;
        src.port = static_cast<UInt16>((t[0] << 8) | t[1]);
        dst.port = static_cast<UInt16>((t[2] << 8) | t[3]);
        // This helper routes TX retries: source is our local endpoint.
        // OnPacket reverses the wire tuple for RX; TX must not reverse it.
        return ShardOf(KeyOf(src, dst));
    }

    bool XtcpStack::SetOption(UInt64 conn_id, options::SocketOption opt,
                              const void* value, UInt32 len) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        MarkSweep(*shard);  // SetOption may arm quickack/keepalive-style timers
        return options::SetOption(*it->second->conn, opt, value, len);
    }

    bool XtcpStack::GetOption(UInt64 conn_id, options::SocketOption opt,
                              void* out, UInt32& len) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        return options::GetOption(*it->second->conn, opt, out, len);
    }

    void XtcpStack::SetKeepalive(UInt64 conn_id, UInt64 idle_us, UInt64 intvl_us, UInt32 cnt) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);  // keepalive timer armed once idle_us > 0
            it->second->conn->SetKeepalive(idle_us, intvl_us, cnt);
        }
    }

    void XtcpStack::SetUserTimeout(UInt64 conn_id, UInt64 timeout_us) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            it->second->conn->SetUserTimeout(timeout_us);
        }
    }

    void XtcpStack::SetFinWait2Timeout(UInt64 conn_id, UInt32 us) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);
            it->second->conn->SetFinWait2Timeout(us);
        }
    }

    void XtcpStack::SetMtuProbeInterval(UInt64 conn_id, UInt32 us) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);  // a probe deadline may already be pending
            it->second->conn->SetMtuProbeInterval(us);
        }
    }

    void XtcpStack::SetTfoCookieFor(const core::Endpoint& remote, const Byte* cookie) noexcept {
        if (NULLPTR == cookie) {
            return;
        }
        const UInt64 h = EndpointKey(remote);
        const UInt64 now = GetTickUs();
        std::lock_guard<std::recursive_mutex> scope(tfo_sync_);
        std::array<Byte, 8> buf{};
        std::memcpy(buf.data(), cookie, 8);
        tfo_cookies_[h] = {buf, now};
        if (kTfoCookieCacheMax < tfo_cookies_.size()) {
            // Bounded cache (audit C-1): evict the least-recently-used entry.
            UInt64 oldest_key = h;
            UInt64 oldest_tick = now;
            for (const auto& kv : tfo_cookies_) {
                if (kv.second.second < oldest_tick) {
                    oldest_tick = kv.second.second;
                    oldest_key = kv.first;
                }
            }
            tfo_cookies_.erase(oldest_key);
        }
    }

    bool XtcpStack::GetTfoCookieFor(const core::Endpoint& remote, Byte out[8]) const noexcept {
        const UInt64 h = EndpointKey(remote);
        std::lock_guard<std::recursive_mutex> scope(tfo_sync_);
        auto it = tfo_cookies_.find(h);
        if (it == tfo_cookies_.end()) {
            return false;
        }
        std::memcpy(out, it->second.first.data(), 8);
        // Refresh the last-use tick so the LRU eviction keeps hot remotes.
        it->second.second = GetTickUs();
        return true;
    }

    void XtcpStack::SetPersistInterval(UInt64 conn_id, UInt32 us) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);  // a persist probe may already be pending
            it->second->conn->SetPersistInterval(us);
        }
    }

    void XtcpStack::SetMd5Key(UInt64 conn_id, const Byte* key, UInt32 len) noexcept {        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);
            it->second->conn->SetMd5Key(key, len);
        }
    }

    void XtcpStack::SetMd5KeyForListener(const core::Endpoint& local, const Byte* key, UInt32 len) noexcept {
        std::lock_guard<std::recursive_mutex> scope(syncobj_);
        const UInt64 h = EndpointKey(local);
        std::array<Byte, 64> buf{};
        UInt32 n = (len > 64) ? 64 : len;
        if (NULLPTR != key && 0 < n) {
            std::memcpy(buf.data(), key, n);
        } else {
            n = 0;
        }
        listener_md5_[h] = buf;
        listener_md5_len_[h] = n;
    }

    bool XtcpStack::Listen(const core::Endpoint& local) noexcept {
        std::lock_guard<std::recursive_mutex> scope(syncobj_);
        // Linux bind semantics: a second listener on the same (family, port)
        // is EADDRINUSE when it would make the first SYN ambiguous - an exact
        // duplicate address, or a wildcard overlapping a specific address.
        for (const core::Endpoint& listener : listeners_) {
            if (listener.family != local.family || listener.port != local.port) {
                continue;
            }
            if (AddrIsWildcard(listener) || AddrIsWildcard(local) ||
                AddrEqual(listener, local)) {
                return false;
            }
        }
        listeners_.push_back(local);
        return true;
    }

    bool XtcpStack::StopListen(const core::Endpoint& local) noexcept {
        std::lock_guard<std::recursive_mutex> scope(syncobj_);
        // Exact-match removal: the caller passes back the endpoint they
        // registered with Listen (same family/port/address). A wildcard
        // overlapping a specific address is NOT removed by this call - it
        // was a separate listener entry.
        for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
            if (it->family == local.family && it->port == local.port &&
                AddrEqual(*it, local)) {
                listeners_.erase(it);
                // Drop the listener's MD5 key entries too: a stale key would
                // silently re-apply to a future re-listen of the same endpoint
                // (security-policy surprise) and the map entries would leak.
                const UInt64 h = EndpointKey(local);
                listener_md5_.erase(h);
                listener_md5_len_.erase(h);
                return true;
            }
        }
        return false;
    }

    UInt64 XtcpStack::Connect(const core::Endpoint& local, const core::Endpoint& remote) noexcept {
        return ConnectWithMd5(local, remote, NULLPTR, 0);
    }

    UInt64 XtcpStack::ConnectWithTfo(const core::Endpoint& local, const core::Endpoint& remote,
                                     const Byte* data, UInt32 len) noexcept {
        // Hard cap: bounded connection memory even under churn/attack.
        // Atomic reservation: fetch_add claims a slot so concurrent creators
        // cannot all pass a plain load (check-then-fetch_add is a TOCTOU race)
        // and overshoot the cap. Roll the slot back if the cap was already
        // reached or a later step fails.
        if (max_conns_ <= conn_count_.fetch_add(1, std::memory_order_relaxed)) {
            conn_count_.fetch_sub(1, std::memory_order_relaxed);
            return 0;
        }
        core::Endpoint eff_local = local;
        if (0 == eff_local.port) {
            bool found = false;
            for (UInt32 attempt = 0; attempt < 4096; ++attempt) {
                const UInt16 port = next_ephemeral_.fetch_add(1, std::memory_order_relaxed);
                eff_local.port = static_cast<UInt16>(49152 + (port % 16384));
                if (IsListening(eff_local)) {
                    continue;
                }
                // Churn guard: skip an ephemeral port whose (local,remote)
                // 4-tuple is already routed in flow_slots_ (live or TIME-WAIT).
                // Reusing it would overwrite flow_slots_[key] and hijack the
                // existing route. The tuple stays mapped until the connection
                // is reclaimed, so TIME-WAIT holds its slot across the 2MSL.
                const core::FlowKey cand = KeyOf(eff_local, remote);
                const UInt64 cand_h = Shard::FlowHashOf(cand);
                Shard* cand_shard = &shards_[static_cast<UInt32>(cand_h % kShardCount)];
                bool in_flight = false;
                {
                    std::lock_guard<std::recursive_mutex> cscope(cand_shard->syncobj_);
                    in_flight = (NULLPTR != cand_shard->FlowFind(cand_h, cand));
                }
                if (!in_flight) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                // All 4096 ephemeral samples hit a live/TIME-WAIT 4-tuple: keep
                // eff_local.port unassigned and fail the connect instead of
                // falling through with the last (in-flight) port and
                // overwriting flow_slots_[key2] on an existing connection.
                conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                return 0;
            }
        }
        const core::FlowKey key2 = KeyOf(eff_local, remote);
        const UInt64 fh2 = Shard::FlowHashOf(key2);
        Shard* shard = &shards_[static_cast<UInt32>(fh2 % kShardCount)];
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        // BUG-2 (TOCTOU): the ephemeral-port scan checked flow_slots_ under a
        // lock released before this point (and an explicit-port caller has no
        // scan at all), so a concurrent same-4-tuple Connect can insert the
        // tuple between that check and the flow_slots_[key2] = id write below,
        // hijacking the earlier connection's route. Same tuple => same shard,
        // so re-verify under this shard's lock. A TIME-WAIT/CLOSED entry may
        // be recycled (RFC 793 tuple reuse, exercised by test_flowmap_reuse),
        // but overwriting a still-live connection strands its in-flight SYN
        // and kills its route.
        ConnEntry* old_entry = shard->FlowFind(fh2, key2);
        if (NULLPTR != old_entry) {
            auto oit = shard->conns_.find(old_entry->id);
            const bool live = (oit != shard->conns_.end() && NULLPTR != oit->second->conn &&
                               core::TcpState::kTimeWait != oit->second->conn->State() &&
                               core::TcpState::kClosed != oit->second->conn->State());
            if (live) {
                conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                return 0;
            }
        }
        const UInt64 id = AllocConnId(next_id_, static_cast<UInt64>(shard - shards_.get()) << 56, shard->conns_);
        if (0 == id) {
            conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
            return 0;
        }
        ConnEntry* entry = NULLPTR;
        core::TcpConn* tcp_conn = NULLPTR;
        if (!shard->slab_.AllocSlot(entry, tcp_conn)) {
            conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
            return 0;
        }
        entry->id = id;
        entry->local = eff_local;
        entry->remote = remote;
        entry->key = key2;
        new (tcp_conn) core::TcpConn(
            core::TcpState::kSynSent, eff_local, remote, DeriveIss(eff_local, remote), 0,
             [this, id, e = entry](buf::BufRef&& p) { EmitLocked(id, e, std::move(p)); });
        entry->conn = tcp_conn;
        entry->conn->SetTwoMsl(two_msl_us_);
        if (0 < rcv_buf_) {
            entry->conn->SetRcvBuf(rcv_buf_);
        }
        if (0 < snd_buf_) {
            entry->conn->SetSndBuf(snd_buf_);
        }
        {
            Byte tfo_cookie[8];
            if (GetTfoCookieFor(remote, tfo_cookie)) {
                entry->conn->SetTfoCookie(tfo_cookie);
            }
            entry->conn->SetTfoCookieCallback([this, remote](const Byte* c) {
                SetTfoCookieFor(remote, c);
            });
        }
        if (!default_cc_.empty()) {
            entry->conn->SetCongestionControl(default_cc_.c_str());
        }
        entry->conn->SetEcnRequested(default_ecn_);
        entry->conn->SetNoSackPermitted(default_no_sack_);
        BindDataPath(id, *shard, entry->local, entry->remote, *entry->conn, false);
        shard->conns_[id] = entry;
        shard->FlowInsert(fh2, key2, shard->conns_[id]);
        // RFC 7413: one SYN carrying the cookie (if known) and the early data.
        shard->conns_[id]->conn->SendSynWithData(data, len);
        MarkSweep(*shard);  // new connection is born dirty: SYN retransmit must be swept
        return id;
    }

    UInt64 XtcpStack::ConnectWithMd5(const core::Endpoint& local, const core::Endpoint& remote,
                                     const Byte* key, UInt32 len) noexcept {
        // Hard cap: bounded connection memory even under churn/attack.
        // Atomic reservation: fetch_add claims a slot so concurrent creators
        // cannot all pass a plain load (check-then-fetch_add is a TOCTOU race)
        // and overshoot the cap. Roll the slot back if the cap was already
        // reached or a later step fails.
        if (max_conns_ <= conn_count_.fetch_add(1, std::memory_order_relaxed)) {
            conn_count_.fetch_sub(1, std::memory_order_relaxed);
            return 0;
        }
        core::Endpoint eff_local = local;
        if (0 == eff_local.port) {
            // Bind semantics: port 0 asks for an ephemeral port (Linux
            // connect() with an unbound socket). Allocate from the IANA
            // dynamic range; collisions are resolved by scanning.
            bool found = false;
            for (UInt32 attempt = 0; attempt < 4096; ++attempt) {
                const UInt16 port = next_ephemeral_.fetch_add(1, std::memory_order_relaxed);
                eff_local.port = static_cast<UInt16>(49152 + (port % 16384));
                if (IsListening(eff_local)) {
                    continue;
                }
                // Churn guard: skip an ephemeral port whose (local,remote)
                // 4-tuple is already routed in flow_slots_ (live or TIME-WAIT).
                // Reusing it would overwrite flow_slots_[key] and hijack the
                // existing route. The tuple stays mapped until the connection
                // is reclaimed, so TIME-WAIT holds its slot across the 2MSL.
                const core::FlowKey cand = KeyOf(eff_local, remote);
                const UInt64 cand_h = Shard::FlowHashOf(cand);
                Shard* cand_shard = &shards_[static_cast<UInt32>(cand_h % kShardCount)];
                bool in_flight = false;
                {
                    std::lock_guard<std::recursive_mutex> cscope(cand_shard->syncobj_);
                    in_flight = (NULLPTR != cand_shard->FlowFind(cand_h, cand));
                }
                if (!in_flight) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                // All 4096 ephemeral samples hit a live/TIME-WAIT 4-tuple: keep
                // eff_local.port unassigned and fail the connect instead of
                // falling through with the last (in-flight) port and
                // overwriting flow_slots_[key2] on an existing connection.
                conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                return 0;
            }
        }
        const core::FlowKey key2 = KeyOf(eff_local, remote);
        const UInt64 fh2 = Shard::FlowHashOf(key2);
        Shard* shard = &shards_[static_cast<UInt32>(fh2 % kShardCount)];
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        // BUG-2 (TOCTOU): the ephemeral-port scan checked flow_slots_ under a
        // lock released before this point (and an explicit-port caller has no
        // scan at all), so a concurrent same-4-tuple Connect can insert the
        // tuple between that check and the flow_slots_[key2] = id write below,
        // hijacking the earlier connection's route. Same tuple => same shard,
        // so re-verify under this shard's lock. A TIME-WAIT/CLOSED entry may
        // be recycled (RFC 793 tuple reuse, exercised by test_flowmap_reuse),
        // but overwriting a still-live connection strands its in-flight SYN
        // and kills its route.
        ConnEntry* old_entry = shard->FlowFind(fh2, key2);
        if (NULLPTR != old_entry) {
            auto oit = shard->conns_.find(old_entry->id);
            const bool live = (oit != shard->conns_.end() && NULLPTR != oit->second->conn &&
                               core::TcpState::kTimeWait != oit->second->conn->State() &&
                               core::TcpState::kClosed != oit->second->conn->State());
            if (live) {
                conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                return 0;
            }
        }
        const UInt64 id = AllocConnId(next_id_, static_cast<UInt64>(shard - shards_.get()) << 56, shard->conns_);
        if (0 == id) {
            conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
            return 0;
        }
        ConnEntry* entry = NULLPTR;
        core::TcpConn* tcp_conn = NULLPTR;
        if (!shard->slab_.AllocSlot(entry, tcp_conn)) {
            conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
            return 0;
        }
        entry->id = id;
        entry->local = eff_local;
        entry->remote = remote;
        entry->key = key2;
        new (tcp_conn) core::TcpConn(
            core::TcpState::kSynSent, eff_local, remote, DeriveIss(eff_local, remote), 0,
             [this, id, e = entry](buf::BufRef&& p) { EmitLocked(id, e, std::move(p)); });
        entry->conn = tcp_conn;
        entry->conn->SetTwoMsl(two_msl_us_);
        if (0 < rcv_buf_) {
            entry->conn->SetRcvBuf(rcv_buf_);
        }
        if (0 < snd_buf_) {
            entry->conn->SetSndBuf(snd_buf_);
        }
        // TSO direct-sends: the backend's TSO cap + no qdisc. The Emit-side
        // TSO gate re-checks the qdisc (SetTxQdisc is startup-only, but a
        // conn bound before the mount would otherwise bypass the qdisc).
        entry->conn->SetTsoTx(0 != (caps_ & ndi::kCapTsoTx) && NULLPTR == tx_qdisc_);
        // RFC 7413: reconnections to a known peer carry its cached TFO
        // cookie automatically; a newly learned cookie updates the cache.
        {
            Byte tfo_cookie[8];
            if (GetTfoCookieFor(remote, tfo_cookie)) {
                entry->conn->SetTfoCookie(tfo_cookie);
            }
            entry->conn->SetTfoCookieCallback([this, remote](const Byte* c) {
                SetTfoCookieFor(remote, c);
            });
        }
        // RFC 2385: the key must be live before the SYN goes out so every
        // segment (including the handshake) carries the signature.
        if (NULLPTR != key && 0 < len) {
            entry->conn->SetMd5Key(key, len);
        }
        if (!default_cc_.empty()) {
            entry->conn->SetCongestionControl(default_cc_.c_str());
        }
        entry->conn->SetEcnRequested(default_ecn_);
        entry->conn->SetNoSackPermitted(default_no_sack_);
        BindDataPath(id, *shard, entry->local, entry->remote, *entry->conn, false);

        shard->conns_[id] = entry;
        shard->FlowInsert(fh2, key2, shard->conns_[id]);
        shard->conns_[id]->conn->SendSyn();
        MarkSweep(*shard);  // new connection is born dirty: SYN retransmit must be swept
        return id;
    }

    void XtcpStack::BindDataPath(UInt64 id, Shard& shard, const core::Endpoint& local,
                                 const core::Endpoint& remote, core::TcpConn& conn,
                                 bool as_accept) noexcept {
        // Bug(state-cb): timer-driven transitions (RTO exhaustion, keepalive
        // abort, FIN-WAIT-2 timeout) never reached the application - the only
        // handler call sat on the packet path (OnPacket). Route the
        // connection's timer-driven notifications back through state_handler_.
        conn.SetStateChangeCallback([this, id](core::TcpState st) {
            if (NULLPTR != state_handler_) {
                state_handler_(id, st);
            }
        });
        conn.SetUrgentCallback([this, id]() {
            if (urgent_handler_) {
                urgent_handler_(id);
            }
        });
        conn.SetRecvHandler([this, &shard, id](const Byte* data, UInt32 len) {
            // Fast path: the find is a per-delivery hash probe; skip it
            // entirely when the shard has no MIMT flows (the common case for
            // plain recv_handler_ connections). empty() is O(1).
            if (!shard.mimt_flows_.empty()) {
                auto it = shard.mimt_flows_.find(id);
                if (it != shard.mimt_flows_.end()) {
                    // Backpressure: report whether the flow accepted the data.
                    // kOk -> true; kNoBuffer (rx queue full) / kClosed -> false so
                    // the TCP layer stops advancing rcv_nxt_ and does not ACK -
                    // the peer RTOs and retransmits instead of silently losing
                    // application data.
                    return (mimt::Result::kOk == it->second->OnData(data, len));
                }
            }
            if (NULLPTR != recv_handler_) {
                // Backpressure must survive the stack wrapper: return the app
                // handler's verdict so the FSM rolls RCV.NXT back and advertises
                // window 0 (RFC 1122 s4.2.3.4). Dropping it (always true) made
                // the peer believe the bytes were delivered while the app
                // silently lost them.
                return recv_handler_(id, data, len);
            }
            return true;  // no handler installed: nothing to backpressure
        });
        // MIMT mode: deliver the flow to the application. Only ACCEPT-side
        // connections (listener SYN / SYN-cookie rebuild) get a flow - a
        // client-connect connection (as_accept == false) must route rx
        // through recv_handler_ instead. Creating a phantom flow for a
        // connect would absorb its rx into a queue the async layer never
        // delivers (silent data loss + backpressure stalls after the 1MB cap).
        bool hook = false;
        if (as_accept) {
            std::lock_guard<std::mutex> lk(mimt_hook_mutex_);
            hook = (NULLPTR != mimt_on_flow_);
            if (hook) {
                auto flow = std::make_shared<mimt::MimtFlow>();
                flow->SetOrigin(id, local, remote);
                shard.mimt_flows_[id] = flow;
                // Stamp which listener accepted this flow: the async layer
                // routes each accept to its per-listener callback via this key
                // (Bug E).
                flow->SetListenerKey(EndpointKey(local));
                flow->SetWriteSink([this, id](const Byte* data, UInt32 len) {
                    Shard* s = ShardOf(id);
                    std::lock_guard<std::recursive_mutex> scope(s->syncobj_);
                    auto it = s->conns_.find(id);
                    if (it == s->conns_.end() || NULLPTR == it->second->conn) {
                        return false;
                    }
                    MarkSweep(*s);  // SendData may arm RTO / buffered data
                    return it->second->conn->SendData(data, len, GetTickUs());
                });
                mimt_on_flow_(flow);
            }
        }
    }

    bool XtcpStack::Send(UInt64 conn_id, const Byte* data, UInt32 len) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        MarkSweep(*shard);  // SendData may arm RTO / buffered data
        return it->second->conn->SendData(data, len, GetTickUs());
    }

    bool XtcpStack::SetCongestionControl(UInt64 conn_id, const char* name) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        MarkSweep(*shard);
        return it->second->conn->SetCongestionControl(name);
    }

    void XtcpStack::SetDefaultCongestionControl(const char* name) noexcept {
        std::lock_guard<std::recursive_mutex> scope(syncobj_);
        default_cc_ = (NULLPTR != name) ? name : "";
    }

    void XtcpStack::ConnStats(UInt64 conn_id, UInt32& inflight, UInt32& cwnd,
                              UInt32& ssthresh, UInt32& snd_wnd, UInt32& retx,
                              UInt64& rto_deadline, UInt32& dup_acks, UInt32& fast_rec,
                              UInt32& front_seq, UInt32& snd_una, UInt16& local_port,
                              UInt16& remote_port) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        inflight = 0;
        cwnd = 0;
        ssthresh = 0;
        snd_wnd = 0;
        retx = 0;
        rto_deadline = 0;
        dup_acks = 0;
        fast_rec = 0;
        front_seq = 0;
        snd_una = 0;
        local_port = 0;
        remote_port = 0;
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return;
        }
        inflight = it->second->conn->SndInflight();
        cwnd = it->second->conn->Cwnd();
        ssthresh = it->second->conn->Ssthresh();
        snd_wnd = it->second->conn->SndWnd();
        retx = it->second->conn->RetransmitCount();
        rto_deadline = it->second->conn->NextRetransmitTime();
        dup_acks = it->second->conn->DupAcks();
        fast_rec = it->second->conn->FastRecovery() ? 1 : 0;
        front_seq = it->second->conn->FrontSeq();
        snd_una = it->second->conn->SndUna();
        local_port = it->second->local.port;
        remote_port = it->second->remote.port;
    }

    bool XtcpStack::TfoSendSynData(UInt64 conn_id, const Byte* data, UInt32 len) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        MarkSweep(*shard);  // SYN retransmit timer armed on the (re)sent SYN
        return it->second->conn->SendSynWithData(data, len);
    }

    void XtcpStack::Close(UInt64 conn_id) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);  // Close arms the FIN retransmit / closing state
            it->second->conn->Close();
        }
    }

    void XtcpStack::Abort(UInt64 conn_id) noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it != shard->conns_.end() && NULLPTR != it->second->conn) {
            MarkSweep(*shard);  // Abort transitions to Closed: must be swept/reclaimed
            it->second->conn->Abort();
        }
    }

    UInt32 XtcpStack::PollAckTimers(UInt32 shard_index) noexcept {
        const UInt64 now = GetTickUs();
        UInt32 sent = 0;
        if (kShardCount <= shard_index) {
            return 0;
        }
        Shard& shard = shards_[shard_index];
        // Fast path: only dirty shards pay for the lock + traversal.
        if (!shard.sweep_hint_.load(std::memory_order_relaxed)) {
            // Global tails still belong to the shard-0 affine caller so a
            // stack that never sweeps shard 0 never leaks fragments.
            if (0 == shard_index) {
                if (0 < ipfrag_.SetCount()) {
                    std::lock_guard<std::recursive_mutex> ipfrag_lock(syncobj_);
                    ipfrag_.Expire(now);
                }
                const core::TimePoint qdisc_next = qdisc_next_pacing_.load(std::memory_order_relaxed);
                if (NULLPTR != tx_qdisc_ && 0 != qdisc_next && qdisc_next <= now) {
                    DrainTxQdisc(now);
                }
            }
            return sent;
        }
        std::lock_guard<std::recursive_mutex> scope(shard.syncobj_);
        shard.sweep_hint_.store(0, std::memory_order_relaxed);
        bool any_dirty = false;
        {
            Shard::TxRetry* chain = shard.tx_retry_head_.exchange(nullptr, std::memory_order_acquire);
            if (NULLPTR != chain) {
                Shard::TxRetry* fifo = NULLPTR;
                Shard::TxRetry* fifo_tail = NULLPTR;
                while (NULLPTR != chain) {
                    Shard::TxRetry* nxt = chain->next;
                    chain->next = fifo;
                    if (NULLPTR == fifo) {
                        fifo_tail = chain;
                    }
                    fifo = chain;
                    chain = nxt;
                }
                while (NULLPTR != fifo) {
                    Shard::TxRetry* nxt = fifo->next;
                    ndi::Packet out;
                    out.data = fifo->ref.Data();
                    out.len = fifo->ref.Len();
                    out.eth_type = fifo->eth_type;
                    out.owned = fifo->ref.Clone();
                    bool tx_ok = false;
                    {
                        std::lock_guard<std::recursive_mutex> tx_scope(backend_tx_mutex_);
                        tx_ok = backend_->Tx(std::move(out));
                    }
                    if (!tx_ok) {
                        fifo_tail->next = shard.tx_retry_head_.load(std::memory_order_relaxed);
                        while (!shard.tx_retry_head_.compare_exchange_weak(
                                   fifo_tail->next, fifo, std::memory_order_release,
                                   std::memory_order_relaxed)) {
                        }
                        break;
                    }
                    delete fifo;
                    shard.tx_retry_count_.fetch_sub(1, std::memory_order_relaxed);
                    fifo = nxt;
                    any_dirty = true;
                }
            }
            if (NULLPTR != shard.tx_retry_head_.load(std::memory_order_relaxed)) {
                any_dirty = true;
            }
        }
        for (auto it = shard.conns_.begin(); it != shard.conns_.end();) {
            ConnEntry* e = it->second;
            if (NULLPTR == e || NULLPTR == e->conn) {
                ++it;
                continue;
            }
            if (!e->conn->TimersDirty()) {
                ++it;
                continue;
            }
            sent += e->conn->OnPoll(now);
            any_dirty = true;
            const bool closed = (core::TcpState::kClosed == e->conn->State());
            const bool tw_done = (core::TcpState::kTimeWait == e->conn->State() &&
                                  0 != e->conn->TimeWaitDeadline() &&
                                  e->conn->TimeWaitDeadline() <= now);
            if (closed || tw_done) {
                {
                    const UInt64 fh = Shard::FlowHashOf(e->key);
                    if (shard.FlowFind(fh, e->key) == e) {
                        shard.FlowErase(fh, e->key);
                    }
                }
                auto mfit = shard.mimt_flows_.find(it->first);
                if (mfit != shard.mimt_flows_.end()) {
                    mfit->second->Close();
                    shard.mimt_flows_.erase(mfit);
                }
                if (NULLPTR != tx_qdisc_ && NULLPTR != tx_qdisc_->ops &&
                    NULLPTR != tx_qdisc_->ops->remove_flow) {
                    const int dropped = tx_qdisc_->ops->remove_flow(tx_qdisc_, it->first);
                    if (0 < dropped) {
                        std::atomic<UInt64>& txc =
                            tx_count_[(static_cast<UInt32>(it->first >> 56)) % kShardCount];
                        txc.fetch_sub(static_cast<UInt64>(dropped), std::memory_order_relaxed);
                    }
                }
                shard.slab_.FreeSlot(e);
                it = shard.conns_.erase(it);
                conn_count_.fetch_sub(1, std::memory_order_relaxed);
                continue;
            }
            ++it;
        }
        shard.sweep_hint_.fetch_or(any_dirty ? 1u : 0u, std::memory_order_relaxed);
        // Global tails owned by the shard-0 affine caller.
        if (0 == shard_index) {
            if (0 < ipfrag_.SetCount()) {
                std::lock_guard<std::recursive_mutex> ipfrag_lock(syncobj_);
                ipfrag_.Expire(now);
            }
            const core::TimePoint qdisc_next = qdisc_next_pacing_.load(std::memory_order_relaxed);
            if (NULLPTR != tx_qdisc_ && 0 != qdisc_next && qdisc_next <= now) {
                DrainTxQdisc(now);
            }
        }
        return sent;
    }

    UInt32 XtcpStack::PollAckTimers() noexcept {
        const UInt64 now = GetTickUs();
        UInt32 sent = 0;
        for (UInt32 i = 0; i < kShardCount; ++i) {
            Shard& shard = shards_[i];
            // Fast path: every connection dirtying path in this stack sets the
            // shard's sweep hint (see the store-true call sites). When no
            // connection has been touched since the last sweep cleared it,
            // nothing can be dirty - skip the lock and the whole map traversal.
            // An idle pool (16K established conns, no timers) costs O(1) here.
            if (!shard.sweep_hint_.load(std::memory_order_relaxed)) {                continue;
            }
            std::lock_guard<std::recursive_mutex> scope(shard.syncobj_);
            // Clear first, then OR in any re-arm. A recv/state callback running
            // inside OnPoll/OnSegment may call Send/Close reentrantly (recursive
            // lock) and MarkSweep the same shard mid-sweep; OR-ing the hint at
            // the end preserves that re-arm so the connection is not missed.
            shard.sweep_hint_.store(0, std::memory_order_relaxed);
            bool any_dirty = false;
            // DMA/PCIe TX backpressure drain (FIFO): retry the packets the
            // backend rejected (ring full). The retries go FIRST so segment
            // ordering is preserved; a still-full ring breaks out and the
            // sweep hint stays armed for the next round.
            // MPSC: exchange the whole chain off the atomic
            // head (lock-free producers appended there), then reverse it in
            // place so the drain runs in FIFO push order; any still-rejected
            // suffix is re-linked onto the head for the next round.
            Shard::TxRetry* chain = shard.tx_retry_head_.exchange(nullptr, std::memory_order_acquire);
            if (NULLPTR != chain) {
                Shard::TxRetry* fifo = NULLPTR;
                Shard::TxRetry* fifo_tail = NULLPTR;  // last node of the FIFO chain (re-link point)
                while (NULLPTR != chain) {
                    Shard::TxRetry* nxt = chain->next;
                    chain->next = fifo;
                    if (NULLPTR == fifo) {
                        fifo_tail = chain;  // first reversed node = FIFO tail
                    }
                    fifo = chain;
                    chain = nxt;
                }
                while (NULLPTR != fifo) {
                    Shard::TxRetry* nxt = fifo->next;
                    ndi::Packet out;
                    out.data = fifo->ref.Data();
                    out.len = fifo->ref.Len();
                    out.eth_type = fifo->eth_type;
                    out.owned = fifo->ref.Clone();  // shared refcount; the node keeps one until accepted
                    bool tx_ok = false;
                    {
                        std::lock_guard<std::recursive_mutex> tx_scope(backend_tx_mutex_);
                        tx_ok = backend_->Tx(std::move(out));
                    }
                    if (!tx_ok) {
                        // ring still full: re-link the remaining suffix
                        // [fifo .. fifo_tail] back onto the head (FIFO
                        // preserved: the suffix keeps its order, and the
                        // suffix's tail points at the old head).
                        fifo_tail->next = shard.tx_retry_head_.load(std::memory_order_relaxed);
                        while (!shard.tx_retry_head_.compare_exchange_weak(
                                   fifo_tail->next, fifo, std::memory_order_release,
                                   std::memory_order_relaxed)) {
                        }
                        break;
                    }
                    delete fifo;
                    shard.tx_retry_count_.fetch_sub(1, std::memory_order_relaxed);
                    fifo = nxt;
                    any_dirty = true;  // keep sweeping while retries remain
                }
            }
            if (NULLPTR != shard.tx_retry_head_.load(std::memory_order_relaxed)) {
                any_dirty = true;  // re-arm: the retry queue still has packets
            }
            for (auto it = shard.conns_.begin(); it != shard.conns_.end();) {
                ConnEntry* e = it->second;
                if (NULLPTR == e || NULLPTR == e->conn) {
                    ++it;
                    continue;
                }
                // Fast path: an idle connection (no armed timers, nothing
                // buffered) is skipped without locking; its dirty flag is
                // set on every timer arm / buffer / close-state transition
                // and cleared by OnPoll. Closing states stay dirty so the
                // reclamation pass below sees them every round.
                if (!e->conn->TimersDirty()) {
                    ++it;
                    continue;
                }
                // One lock per connection for all timers + buffered flush.
                sent += e->conn->OnPoll(now);
                // Keep the sweep hint armed while any connection still needs
                // polling (re-armed timers, buffered data, closing states).
                if (e->conn->TimersDirty()) {
                    any_dirty = true;
                }
                // Reclaim closed connections (FIN/RST complete) immediately,
                // and TIME-WAIT connections once the 2MSL deadline elapses
                // (RFC 793) - otherwise they linger forever and exhaust the
                // connection cap.
                const bool closed = (core::TcpState::kClosed == e->conn->State());
                const bool tw_done = (core::TcpState::kTimeWait == e->conn->State() &&
                                      0 != e->conn->TimeWaitDeadline() &&
                                      e->conn->TimeWaitDeadline() <= now);
                if (closed || tw_done) {
                    // Guard: only erase the flow route if it still points at
                    // this connection. A same-4-tuple reconnect may have
                    // overwritten the route with the new connection - erasing
                    // unconditionally would delete the live route.
                    {
                        const UInt64 fh = Shard::FlowHashOf(e->key);
                        if (shard.FlowFind(fh, e->key) == e) {
                            shard.FlowErase(fh, e->key);
                        }
                    }
                    // MIMT reclaim (Bug A): the underlying connection is gone,
                    // so the flow can never be dispatched again. Complete every
                    // pending async operation (AsyncRead/AsyncWrite) with
                    // kClosed before erasing - otherwise they hang forever.
                    auto mfit = shard.mimt_flows_.find(it->first);
                    if (mfit != shard.mimt_flows_.end()) {
                        mfit->second->Close();
                        shard.mimt_flows_.erase(mfit);
                    }
                    // Qdisc flow reclaim (Bug B2): a closed connection can never
                    // enqueue again, yet its FQ flow (keyed by conn_id) would
                    // linger in by_id/flows forever, growing the flow table
                    // without bound under short-connection churn and letting a
                    // stale pacing state leak into a conn_id-reusing successor.
                    if (NULLPTR != tx_qdisc_ && NULLPTR != tx_qdisc_->ops &&
                        NULLPTR != tx_qdisc_->ops->remove_flow) {
                        // Dropped queued segments never reached the wire:
                        // subtract them from this shard's tx counter (M4).
                        const int dropped = tx_qdisc_->ops->remove_flow(tx_qdisc_, it->first);
                        if (0 < dropped) {
                            std::atomic<UInt64>& txc =
                                tx_count_[(static_cast<UInt32>(it->first >> 56)) % kShardCount];
                            txc.fetch_sub(static_cast<UInt64>(dropped), std::memory_order_relaxed);
                        }
                    }
                    // Return the entry's slot to the slab (destroys the
                    // TcpConn; the flow_slots_ route was already erased above).
                    shard.slab_.FreeSlot(e);
                    it = shard.conns_.erase(it);
                    conn_count_.fetch_sub(1, std::memory_order_relaxed);
                    continue;
                }
                ++it;
            }
            // A sweep that found no dirty connection leaves the hint clear so
            // the next round skips this shard entirely (O(1) idle sweep). OR
            // in any re-arm issued reentrantly by callbacks during this sweep.
            // fetch_or: a lock-free MarkSweep from a foreign
            // shard's retry push can land between the load and the store of
            // a plain store(load||any) - the hint would be swallowed and the
            // retry chain starve one round. fetch_or is an atomic RMW, so a
            // concurrent store(true) is never lost.
            shard.sweep_hint_.fetch_or(any_dirty ? 1u : 0u, std::memory_order_relaxed);
        }
        // IP fragment reassembly (RFC 791): expire sets idle past the timeout
        // so partial fragments cannot accumulate forever. The atomic set
        // count is the cheap idle hint - with no live sets the lock and the
        // table walk are skipped entirely (an idle stack costs O(1) here,
        // not a global lock + empty-table sweep every round).
        if (0 < ipfrag_.SetCount()) {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            ipfrag_.Expire(now);
        }
        // Qdisc pacing clock: drain packets whose pacing deadline elapsed.
        const core::TimePoint qdisc_next = qdisc_next_pacing_.load(std::memory_order_relaxed);
        if (NULLPTR != tx_qdisc_ && 0 != qdisc_next && qdisc_next <= now) {
            DrainTxQdisc(now);
        }
        return sent;
    }

    UInt64 XtcpStack::ConnTimeWaitDeadline(UInt64 conn_id) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return 0;
        }
        return it->second->conn->TimeWaitDeadline();
    }

    UInt32 XtcpStack::ConnectionCount() const noexcept {
        return conn_count_.load(std::memory_order_relaxed);
    }

    UInt64 XtcpStack::FragmentsReassembled() const noexcept {
        return ipfrag_.ReassembledCount();
    }

    core::TcpState XtcpStack::ConnectionState(UInt64 conn_id) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return core::TcpState::kClosed;
        }
        return it->second->conn->State();
    }

    bool XtcpStack::ConnectionExists(UInt64 conn_id) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        return (it != shard->conns_.end() && NULLPTR != it->second->conn);
    }

    bool XtcpStack::GetLocalEndpoint(UInt64 conn_id, core::Endpoint& out) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        out = it->second->local;
        return true;
    }

    bool XtcpStack::GetRemoteEndpoint(UInt64 conn_id, core::Endpoint& out) const noexcept {
        Shard* shard = ShardOf(conn_id);
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        auto it = shard->conns_.find(conn_id);
        if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
            return false;
        }
        out = it->second->remote;
        return true;
    }

    UInt32 XtcpStack::DispatchMimt() noexcept {
        UInt32 fired = 0;
        for (UInt32 i = 0; i < kShardCount; ++i) {
            fired += DispatchMimt(i);
        }
        return fired;
    }

    UInt32 XtcpStack::DispatchMimt(UInt32 shard_index) noexcept {
        if (shard_index >= kShardCount) {
            return 0;
        }
        UInt32 fired = 0;
        Shard& shard = shards_[shard_index];
        std::lock_guard<std::recursive_mutex> scope(shard.syncobj_);
        for (auto& kv : shard.mimt_flows_) {
            fired += kv.second->Dispatch();
        }
        return fired;
    }

    void XtcpStack::OnPacket(buf::BufRef&& packet) noexcept {
        const Byte* data = packet.Data();
        UInt32 len = packet.Len();
        if (NULLPTR == data || len < 20) {
            return;
        }
        // MIMT reclaim (Bug A): a connection is being erased outside the
        // normal PollAckTimers reclamation path (MD5/accept rejection before
        // the handshake completes). BindDataPath has already registered a
        // flow in mimt_flows_ and delivered it to the app (stack.cpp:1337-1345), so erasing the connection without reclaiming the flow would
        // strand a ghost flow whose AsyncRead never completes. Mirror the
        // PollAckTimers reclamation (Close + erase).
        const auto ReclaimMimtFlow = [](Shard* shard, UInt64 id) noexcept {
            auto mfit = shard->mimt_flows_.find(id);
            if (mfit != shard->mimt_flows_.end()) {
                mfit->second->Close();
                shard->mimt_flows_.erase(mfit);
            }
        };
        // Qdisc flow reclaim (Bug B2, mirror of PollAckTimers stack.cpp:1610-1626):
        // the rejection's Abort() RST may have entered an FQ flow keyed by
        // conn_id (SendOne enqueue), and remove_flow is what releases it.
        // Without it the flow lingers in by_id/flows forever (FqDequeue keeps
        // empty flows registered) and a conn_id-reusing successor inherits the
        // stale pacing state.
        const auto ReclaimQdiscFlow = [this](UInt64 conn_id) noexcept {
            if (NULLPTR != tx_qdisc_ && NULLPTR != tx_qdisc_->ops &&
                NULLPTR != tx_qdisc_->ops->remove_flow) {
                // The qdisc drops the closed connection's queued segments
                // (they can never be retransmitted); return the dropped
                // count so the tx counter stops over-reporting (those
                // packets never reached the wire, audit M4).
                const int dropped = tx_qdisc_->ops->remove_flow(tx_qdisc_, conn_id);
                if (0 < dropped) {
                    std::atomic<UInt64>& txc =
                        tx_count_[(static_cast<UInt32>(conn_id >> 56)) % kShardCount];
                    txc.fetch_sub(static_cast<UInt64>(dropped), std::memory_order_relaxed);
                }
            }
        };
        const Byte version = static_cast<Byte>(data[0] >> 4);
        core::Endpoint src, dst;
        UInt32 tcp_off = 0;
#ifdef XTCP_CHECKSUM_VALIDATE
        UInt32 tcp_len = 0;  // TCP header+payload bytes (excludes Ethernet padding)
#endif
        buf::BufRef reassembled;
        core::FragKey fkey;
        core::Fragment frag;
        bool is_fragment = false;
        // RFC 3168 s6.1.3: CE detection - the receiver must echo ECE on ACKs
        // once a CE-marked IP packet (ECN field = 11) is received. Captured
        // from the first fragment's header (RFC 3168 s5.3: fragments of a
        // CE-marked datagram all carry CE, and the reassembled datagram is
        // CE-marked).
        bool ce_marked = false;

        if (4 == version) {
            core::Ip4Hdr ip4;
            if (!core::ParseIp4(data, len, ip4)) {
                return;
            }
            // ECN field = low 2 bits of the IPv4 TOS byte (byte 1).
            ce_marked = (3 == (data[1] & 0x03));
#ifdef XTCP_CHECKSUM_VALIDATE
            // RFC 791: an intact IPv4 header folds to 0x0000. Validates the
            // header of every IPv4 packet (fragments included) before any
            // field is trusted; a corrupt header is dropped.
            if (!VerifyIp4HeaderChecksum(data, ip4.hdr_len)) {
                return;
            }
#endif
            src.family = 4;
            src.addr[0] = ip4.src;
            dst.addr[0] = ip4.dst;
            tcp_off = ip4.payload_off;
#ifdef XTCP_CHECKSUM_VALIDATE
            // total_len bounds the datagram (len may carry Ethernet padding).
            tcp_len = ip4.total_len - tcp_off;
#endif
            // RFC 1191 path-MTU discovery: an ICMP "fragmentation needed"
            // carries the original TCP header; lower that flow's MSS.
            if (1 == ip4.proto) {
                core::IcmpFragNeeded icmp;
                if (core::ParseIcmpFragNeeded(data, len, icmp) && icmp.valid) {
                    core::Endpoint orig_src, orig_dst;
                    orig_src.family = icmp.family;
                    for (UInt32 i = 0; i < 4; ++i) {
                        orig_src.addr[i] = icmp.src_addr[i];
                    }
                    orig_src.port = icmp.src_port;
                    orig_dst.family = icmp.family;
                    for (UInt32 i = 0; i < 4; ++i) {
                        orig_dst.addr[i] = icmp.dst_addr[i];
                    }
                    orig_dst.port = icmp.dst_port;
                    const core::FlowKey key = KeyOf(orig_src, orig_dst);
                    const UInt64 fh = Shard::FlowHashOf(key);
                    Shard* shard = &shards_[static_cast<UInt32>(fh % kShardCount)];
                    std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
                    ConnEntry* pmtu_entry = shard->FlowFind(fh, key);
                    if (NULLPTR != pmtu_entry && NULLPTR != pmtu_entry->conn) {
                        MarkSweep(*shard);  // OnMtuReduced arms the re-probe deadline
                        pmtu_entry->conn->OnMtuReduced(icmp.mtu);
                    }
                }
                return;  // ICMP is not TCP traffic
            }
            // Protocol gate: only TCP (proto 6) may reach ParseTcp below. A
            // non-TCP packet (e.g. UDP=17) whose 4-tuple collides with a live
            // flow must not have its header decoded as a TCP header (protocol
            // confusion / TCP injection). ICMP was handled above and returns.
            if (6 != ip4.proto) {
                return;
            }
            // RFC 791 reassembly: a fragmented TCP datagram must be rebuilt
            // before parsing the TCP header (non-first fragments carry only
            // payload, no TCP header). Gate to TCP so ICMP/other keep the
            // existing path.
            if (6 == ip4.proto && (0 != (ip4.flags & 0x01) || 0 != ip4.frag_off)) {
                is_fragment = true;
                fkey.version = 4;
                fkey.src[0] = ip4.src;
                fkey.dst[0] = ip4.dst;
                fkey.id = ip4.id;
                fkey.proto = ip4.proto;
                frag.offset = ip4.frag_off;
                frag.more = 0 != (ip4.flags & 0x01);
                frag.data = data + ip4.payload_off;
                // total_len bounds the datagram (len may carry Ethernet
                // padding); padding in the final fragment would inflate the
                // reassembled length and trip the overlap rejection.
                frag.len = static_cast<UInt32>(ip4.total_len) - ip4.payload_off;
            }
        } else if (6 == version) {
            core::Ip6Hdr ip6;
            if (!core::ParseIp6(data, len, ip6)) {
                return;
            }
            // ECN field = low 2 bits of the IPv6 traffic-class octet (the
            // low nibble of byte 1; ECT(0) = 0b10, CE = 0b11).
            ce_marked = (3 == ((data[1] >> 4) & 0x03));
            src.family = 6;
            dst.family = 6;
            for (UInt32 i = 0; i < 4; ++i) {
                src.addr[i] = ip6.src[i];
                dst.addr[i] = ip6.dst[i];
            }
            tcp_off = ip6.payload_off;
#ifdef XTCP_CHECKSUM_VALIDATE
            // IPv6 payload length bounds the segment (RFC 8200); exclude any
            // padding beyond the announced payload.
            tcp_len = static_cast<UInt32>(40 + ip6.payload_len) - tcp_off;
#endif
            // Protocol gate: only TCP (proto 6) may reach ParseTcp below. A
            // non-TCP packet (ICMPv6=58, UDP=17, ...) whose 4-tuple collides
            // with a live flow must not have its header decoded as a TCP
            // header. ICMPv6 has no PMTU/frag-needed handling in this path.
            if (6 != ip6.proto) {
                return;
            }
            // RFC 8200 reassembly: an IPv6 fragment header makes the packet
            // a fragment; non-first fragments carry only payload data.
            if (6 == ip6.proto && (0 != ip6.frag_more || 0 != ip6.frag_off)) {
                is_fragment = true;
                fkey.version = 6;
                for (UInt32 i = 0; i < 4; ++i) {
                    fkey.src[i] = ip6.src[i];
                    fkey.dst[i] = ip6.dst[i];
                }
                fkey.id = ip6.frag_id;
                fkey.proto = ip6.proto;
                frag.offset = ip6.frag_off;
                frag.more = 0 != ip6.frag_more;
                frag.data = data + ip6.payload_off;
                // Fragment data extends from after the fragment header to the
                // end of the IPv6 payload (40 + payload_len).
                frag.len = static_cast<UInt32>(40 + ip6.payload_len) - ip6.payload_off;
            }
        } else {
            return;
        }
        // RFC 791 / RFC 8200: reassemble fragmented TCP segments before the
        // TCP parse below. Add returns 1 on a complete datagram (reassembled
        // is the full TCP segment), 0 while partial, -1 on discard.
        if (is_fragment) {
            Int32 rc = 0;
            {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                rc = ipfrag_.Add(GetTickUs(), fkey, frag, reassembled);
            }
            if (1 != rc) {
                return;  // still partial (0) or discarded/oversized (-1)
            }
            data = reassembled.Data();
            len = reassembled.Len();
            tcp_off = 0;
#ifdef XTCP_CHECKSUM_VALIDATE
            tcp_len = len;
#endif
        }
        if (tcp_off >= len) {
            return;
        }
        core::TcpHdr tcp;
        if (!core::ParseTcp(data + tcp_off, len - tcp_off, tcp)) {
            return;
        }
#ifdef XTCP_CHECKSUM_VALIDATE
        // RFC 793: verify the TCP checksum (pseudo-header + TCP header incl.
        // the checksum field + payload must fold to 0x0000). Runs on the
        // reassembled segment too (reassembly replaces data/len above).
        // MD5 connections (RFC 2385) are covered by the same TCP checksum;
        // the digest lives in the header/payload this sum validates.
        if (!VerifyTcpChecksum(src, dst, data + tcp_off, tcp_len)) {
            return;  // corrupt segment: drop
        }
#endif
        src.port = tcp.sport;
        dst.port = tcp.dport;

        // Resolve the flow (local=dst, remote=src), then its shard. One hash
        // computation serves both the shard selection and the flat-table
        // bucket probe (perf #3).
        const core::FlowKey key = KeyOf(dst, src);
        const UInt64 fh = Shard::FlowHashOf(key);
        Shard* shard = &shards_[static_cast<UInt32>(fh % kShardCount)];
        std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
        ConnEntry* routed = shard->FlowFind(fh, key);
        if (NULLPTR == routed) {
            // RFC 4987 SYN-cookie mode: once live connections reach the
            // threshold, answer SYNs statelessly (no connection state) and
            // rebuild the connection when the client's cookie ACK returns.
            // Clamp to max_conns_: a configured threshold above the hard
            // connection cap is unreachable and would silently disable cookie
            // mode (conn_count_ can never exceed max_conns_).
            UInt32 threshold = (0 < syncookie_threshold_) ? syncookie_threshold_ : max_conns_;
            if (threshold > max_conns_) {
                threshold = max_conns_;
            }
            if (tcp.IsSyn() && (IsListening(dst) || NULLPTR != mimt_on_flow_)) {
                if (threshold <= conn_count_.load(std::memory_order_relaxed)) {
                    // RFC 2385 consistency: a listener that requires MD5 must
                    // not be bypassed by cookie mode - verify the SYN's
                    // signature before answering statelessly, and sign the
                    // stateless SYN+ACK with the listener's key (an unsigned
                    // cookie SYN+ACK is dropped by a signed-only client).
                    std::array<Byte, 64> cookie_key{};
                    UInt32 cookie_key_len = 0;
                    {
                        std::lock_guard<std::recursive_mutex> lk(syncobj_);
                        if (LookupListenerMd5Key(dst, cookie_key.data(), &cookie_key_len)) {
                            if (!core::TcpConn::VerifyMd5Segment(cookie_key.data(), cookie_key_len, dst, src,
                                                                 const_cast<Byte*>(data + tcp_off),
                                                                 len - tcp_off)) {
                                return;  // unsigned/invalid SYN: no cookie answer
                            }
                        }
                    }
                    // Cookie response: ISN encodes the cookie; no state.
                    // RFC 879 / RFC 1122 s4.2.2.6: an absent MSS option - or
                    // an MSS option with value 0 - means the client's receive
                    // MSS is the 536 default. The cookie table has no 536
                    // entry, so the default maps to the 512 bucket (the
                    // largest table value <= 536); leaving the index at 0
                    // would tell the rebuilt connection to send 1460-byte
                    // segments to a 536-byte client (mirror of the stateful
                    // path, which forces 536 for the same input).
                    core::TcpOpts syn_opts;
                    Byte mss_index = 2;
                    if (core::ParseTcpOpts(data + tcp_off, len - tcp_off, tcp.hdr_len, syn_opts) &&
                        syn_opts.has_mss && 0 < syn_opts.mss) {
                        mss_index = (1460 <= syn_opts.mss) ? 0 : ((1024 <= syn_opts.mss) ? 1
                                  : ((512 <= syn_opts.mss) ? 2 : 3));
                    }
                    const UInt32 time_sec = static_cast<UInt32>(GetTickUs() / 1000000);
                    const UInt32 cookie = syncookies_.Compute(src.addr, dst.addr, src.port, dst.port,
                                                              tcp.seq, time_sec, mss_index);
                    // RFC 7323: the stateless SYN+ACK offers our window scale
                    // and scales the window field only when the client itself
                    // offered WSOPT (both-sides rule).
                    buf::BufRef synack = core::TcpConn::BuildSynAckPacket(dst, src, cookie, tcp.seq + 1,
                                                                           syn_opts.has_wscale
                                                                               ? core::TcpConn::kWindowScaleOffer
                                                                               : 0,
                                                                           cookie_key.data(), cookie_key_len);
                    if (!synack.IsEmpty()) {
                        ndi::Packet out;
                        out.data = synack.Data();
                        out.len = synack.Len();
                        out.eth_type = kIpv4;
                        out.owned = std::move(synack);
                        // Bug 1: the stateless cookie SYN+ACK bypasses
                        // EmitLocked (no conn_id exists yet), so count it
                        // manually - mirror of EmitLocked's per-packet count.
                        tx_count_[static_cast<UInt32>(shard - shards_.get())].fetch_add(1, std::memory_order_relaxed);
                        EmitOrRetry(*shard, std::move(out));
                    }
                    return;
                }
                // SYN-flood bound: refuse once the hard cap is reached.
                // Atomic reservation: conn_count_ is stack-level (cross-shard),
                // so a plain load followed by a later fetch_add would let
                // concurrent shards over-admit. Claim a slot now and roll it
                // back on every path that does not create a connection.
                if (max_conns_ <= conn_count_.fetch_add(1, std::memory_order_relaxed)) {
                    conn_count_.fetch_sub(1, std::memory_order_relaxed);
                    return;
                }
                const UInt64 id = AllocConnId(next_id_, static_cast<UInt64>(shard - shards_.get()) << 56, shard->conns_);
                if (0 == id) {
                    conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                    return;
                }
                ConnEntry* entry = NULLPTR;
                core::TcpConn* tcp_conn = NULLPTR;
                if (!shard->slab_.AllocSlot(entry, tcp_conn)) {
                    conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                    return;
                }
                entry->id = id;
                entry->local = dst;
                entry->remote = src;
                entry->key = key;
                new (tcp_conn) core::TcpConn(
                    core::TcpState::kSynRcvd, dst, src, DeriveIss(dst, src), tcp.seq,
                    [this, id, e = entry](buf::BufRef&& p) { EmitLocked(id, e, std::move(p)); });
                entry->conn = tcp_conn;
                entry->conn->SetTwoMsl(two_msl_us_);
        if (0 < rcv_buf_) {
            entry->conn->SetRcvBuf(rcv_buf_);
        }
        if (0 < snd_buf_) {
            entry->conn->SetSndBuf(snd_buf_);
        }
                if (!default_cc_.empty()) {
            entry->conn->SetCongestionControl(default_cc_.c_str());
        }
                // RFC 3168 s6.1.1: the server includes ECE in its SYN+ACK
                // ONLY when the client's SYN offered ECN (ECE+CWR together).
                // Offering ECN to a client that did not request it is a
                // negotiation violation (and, with the default ON, would put
                // every non-ECN peer on an ECN connection).
                const bool client_offered_ecn =
                    (tcp.flags & (core::kFlagEce | core::kFlagCwr)) ==
                    (core::kFlagEce | core::kFlagCwr);
                entry->conn->SetEcnRequested(default_ecn_ && client_offered_ecn);
                BindDataPath(id, *shard, entry->local, entry->remote, *entry->conn, true);
                // RFC 7323: parse the peer's WSOPT from the SYN; the peer
                // advertises its window already scaled by this factor.
                {
                    core::TcpOpts opts;
                    if (core::ParseTcpOpts(data + tcp_off, len - tcp_off, tcp.hdr_len, opts)) {
                        if (opts.has_wscale) {
                            entry->conn->SetSndWscale(opts.wscale);
                        }
                        // RFC 7323 both-sides rule: our advertised window
                        // scales only when the client answered our WSOPT offer
                        // (the SYN+ACK below carries the offer + scaled window).
                        entry->conn->SetRcvWscale(
                            opts.has_wscale ? core::TcpConn::kWindowScaleOffer : 0);
                        if (opts.has_mss) {
                            entry->conn->SetPeerMss(opts.mss);
                        } else {
                            // RFC 1122 s4.2.2.6: the client's SYN carried no
                            // MSS option - default to 536-byte segments.
                            entry->conn->SetPeerMss(536);
                        }
                        // RFC 2018: the client advertised SACK-permitted on its
                        // SYN - we may send SACK blocks on this connection
                        // (the client learns the same from our SYN+ACK). The
                        // local kTcpNoSackPermitted suppression wins: the
                        // connection stays SACK-less even when the peer
                        // offered (both sides must offer, tcp.h NoSackPermitted).
                        entry->conn->SetSackOk(opts.has_sack && !entry->conn->NoSackPermitted());
                        // RFC 7323: the client offered timestamps on its SYN -
                        // our SYN+ACK answers the offer, activating the option.
                        entry->conn->SetPeerTimestampsOffered(opts.has_timestamp);
                    } else {
                        // RFC 1122 s4.2.2.6: a malformed option stream yields
                        // no usable negotiation - behave exactly as if no
                        // options were present: 536-byte segments, no window
                        // scaling, no SACK. (The constructor default 1460
                        // would otherwise diverge from the absent-option 536.)
                        entry->conn->SetPeerMss(536);
                    }
                }
                // TCP Fast Open (RFC 7413): accept SYN-carried early data
                // ONLY when the client presents a valid cookie (a cookie-less
                // SYN+data is a spoof vector - the cookie proves the client
                // completed a prior handshake).
                {
                    core::TcpOpts opts;
                    const bool has_opts =
                        core::ParseTcpOpts(data + tcp_off, len - tcp_off, tcp.hdr_len, opts);
                    const UInt32 early_len = len - tcp_off - tcp.hdr_len;
                    if (0 < early_len && early_len <= core::kTfoMaxEarlyData &&
                        has_opts && opts.has_tfo) {
                        // RFC 7413 4.3: TFO and TCP-MD5 are mutually exclusive.
                        // The cookie check runs before the listener's MD5
                        // signature check (which may RST this SYN), so a
                        // listener with an MD5 key must not accept SYN-carried
                        // early data even when the cookie validates - a stale
                        // non-MD5 cookie must not unlock early data on an
                        // MD5 connection.
                        bool md5_listener = false;
                        {
                            std::lock_guard<std::recursive_mutex> lk(syncobj_);
                            Byte probe[64];
                            UInt32 probe_len = 0;
                            md5_listener = LookupListenerMd5Key(dst, probe, &probe_len);
                        }
                        if (!md5_listener && entry->conn->VerifyTfoCookie(opts.tfo_cookie)) {
                            entry->conn->AcceptEarlyData(data + tcp_off + tcp.hdr_len, early_len);
                        }
                    }
                }
                // RFC 2385: inherit the listener's MD5 key (exact or wildcard).
                {
                    std::lock_guard<std::recursive_mutex> lk(syncobj_);
                    Byte inherited[64];
                    UInt32 inherited_len = 0;
                    if (LookupListenerMd5Key(dst, inherited, &inherited_len)) {
                        entry->conn->SetMd5Key(inherited, inherited_len);
                        // A client that does not sign its SYN is refused
                        // cleanly (RST) instead of being stranded in a
                        // half-open state where its ACKs are dropped.
                        if (!core::TcpConn::VerifyMd5Segment(inherited, inherited_len,
                                                             dst, src,
                                                             const_cast<Byte*>(data + tcp_off),
                                                             len - tcp_off)) {
                            shard->conns_[id] = entry;
                            shard->FlowInsert(fh, key, shard->conns_[id]);
                            shard->conns_[id]->conn->Abort();  // RST
                            shard->FlowErase(fh, key);
                            ReclaimMimtFlow(shard, id);
                            ReclaimQdiscFlow(id);
                            // Return the slot to the slab BEFORE erasing the
                            // map entry - otherwise the ConnEntry and its
                            // TcpConn (retrans_queue deque + callback
                            // std::functions) leak (the sweep never sees the
                            // erased id again). LeakSanitizer: 616B/4
                            // allocations per rejected SYN.
                            shard->slab_.FreeSlot(entry);
                            shard->conns_.erase(id);
                            conn_count_.fetch_sub(1, std::memory_order_relaxed);
                            return;
                        }
                    }
                }
                shard->conns_[id] = entry;
                shard->FlowInsert(fh, key, shard->conns_[id]);
                // Server-mode acceptance: the application may refuse the
                // connection (RST) or accept it (SYN+ACK follows).
                if (NULLPTR != accept_handler_ &&
                    !accept_handler_(id, shard->conns_[id]->remote, shard->conns_[id]->local)) {
                    shard->conns_[id]->conn->Abort();
                    shard->FlowErase(fh, key);
                    ReclaimMimtFlow(shard, id);
                    ReclaimQdiscFlow(id);
                    shard->slab_.FreeSlot(entry);  // see the MD5-reject site: erase must free the slot
                    shard->conns_.erase(id);
                    conn_count_.fetch_sub(1, std::memory_order_relaxed);
                    return;
                }
                shard->conns_[id]->conn->SendSynAck();
                MarkSweep(*shard);  // new connection is born dirty: SYN+ACK retransmit must be swept
                return;
            } else if (tcp.IsSyn()) {
                // RFC 793: connection refused - no listener on this port.
                // A RST (with ACK = SYN seq+1) tells the client immediately
                // instead of silently dropping (port-scan visibility). A SYN
                // flood against a closed port must NOT reflect 1:1 RSTs
                // (Linux tcp_rst_ratelimit): at most 100 closed-port RSTs per
                // 1s window; excess RSTs are dropped silently.
                static constexpr UInt64 kClosedRstWindowUs = 1000000;
                static constexpr UInt32 kClosedRstLimit = 100;
                const core::TimePoint now = GetTickUs();
                if (now >= closed_rst_window_.load(std::memory_order_relaxed)) {
                    closed_rst_window_.store(now + kClosedRstWindowUs, std::memory_order_relaxed);
                    closed_rst_count_.store(0, std::memory_order_relaxed);
                }
                if (closed_rst_count_.load(std::memory_order_relaxed) < kClosedRstLimit) {
                    closed_rst_count_.fetch_add(1, std::memory_order_relaxed);
                    SendClosedPortRst(backend_, backend_tx_mutex_, dst, src, tcp.seq);
                }
                return;
            }
            // RFC 4987: a cookie ACK arrives with no flow state - verify the
            // cookie and rebuild the connection statelessly.
            if (tcp.IsAck() && !tcp.IsSyn()) {
                // Atomic reservation: conn_count_ is stack-level (cross-shard),
                // so a plain load followed by a later fetch_add would let
                // concurrent shards over-admit. Claim a slot now and roll it
                // back on every path that does not rebuild a connection.
                // A valid cookie proves a completed handshake, so completions
                // are admitted up to the cap itself (refusing at old == max
                // would strand every client exactly while cookie mode runs);
                // the bound is enforced past it (old > max refused), so
                // conn_count_ stays <= max_conns_ + 1.
                if (max_conns_ < conn_count_.fetch_add(1, std::memory_order_relaxed)) {
                    conn_count_.fetch_sub(1, std::memory_order_relaxed);
                    return;
                }
                const UInt32 time_sec = static_cast<UInt32>(GetTickUs() / 1000000);
                Byte mss_index = 0;
                if (syncookies_.Verify(tcp.ack - 1, tcp.ack,
                                       src.addr, dst.addr, src.port, dst.port,
                                       tcp.seq - 1, time_sec, 60, mss_index)) {
                    // RFC 2385 consistency: rebuild only if the cookie ACK is
                    // signed when the listener requires MD5 (no bypass), and
                    // carry the key over to the rebuilt connection so its
                    // segments stay signed/verified (an unsigned rebuild
                    // connection would be an MD5 bypass and its outbound
                    // segments would be dropped by the signed-only peer).
                    std::array<Byte, 64> rebuild_key{};
                    UInt32 rebuild_key_len = 0;
                    {
                        std::lock_guard<std::recursive_mutex> lk(syncobj_);
                        if (LookupListenerMd5Key(dst, rebuild_key.data(), &rebuild_key_len)) {
                            if (!core::TcpConn::VerifyMd5Segment(rebuild_key.data(), rebuild_key_len, dst, src,
                                                                 const_cast<Byte*>(data + tcp_off),
                                                                 len - tcp_off)) {
                                conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                                return;  // unsigned cookie ACK refused
                            }
                        }
                    }
                    // The cookie encodes the MSS index in 3 bits; only 0-3 are
                    // ever emitted by the encoder. Decode with the full 3-bit
                    // mask and an 8-entry table (duplicated 0-3) so a forged
                    // index 4-7 maps consistently instead of being silently
                    // remapped by a 2-bit mask (audit B-3).
                    static const UInt16 kCookieMss[8] = { 1460, 1024, 512, 256, 1460, 1024, 512, 256 };
                    const UInt16 mss = kCookieMss[mss_index & 0x07];
                    const UInt64 id = AllocConnId(next_id_, static_cast<UInt64>(shard - shards_.get()) << 56, shard->conns_);
                    if (0 == id) {
                        conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                        return;
                    }
                    ConnEntry* entry = NULLPTR;
                    core::TcpConn* tcp_conn = NULLPTR;
                    if (!shard->slab_.AllocSlot(entry, tcp_conn)) {
                        conn_count_.fetch_sub(1, std::memory_order_relaxed);  // roll back the reservation
                        return;
                    }
                    entry->id = id;
                    entry->local = dst;
                    entry->remote = src;
                    entry->key = key;
                    // Established directly: iss = cookie, rcv_nxt = ACK seq.
                    new (tcp_conn) core::TcpConn(
                        core::TcpState::kEstablished, dst, src, tcp.ack - 1, tcp.seq - 1,
                        [this, id, e = entry](buf::BufRef&& p) { EmitLocked(id, e, std::move(p)); });
                    entry->conn = tcp_conn;
                    entry->conn->SetTwoMsl(two_msl_us_);
        if (0 < rcv_buf_) {
            entry->conn->SetRcvBuf(rcv_buf_);
        }
        if (0 < snd_buf_) {
            entry->conn->SetSndBuf(snd_buf_);
        }
                    if (0 < rebuild_key_len) {
                        entry->conn->SetMd5Key(rebuild_key.data(), rebuild_key_len);
                    }
                    if (!default_cc_.empty()) {
            entry->conn->SetCongestionControl(default_cc_.c_str());
        }
        entry->conn->SetEcnRequested(default_ecn_);
        entry->conn->SetNoSackPermitted(default_no_sack_);
                    // RFC 3168 note: the normal accept
                    // path gates ecn_requested_ on the client's ECE+CWR offer,
                    // but the SYN-cookie rebuild cannot - the cookie encodes
                    // no ECN offer. The setting is inert here: this path
                    // establishes directly (no SYN+ACK), so ecn_active_ is
                    // never armed (the ECE gates live in the SYN+ACK/completing-
                    // ACK paths) and the connection runs non-ECN regardless.
                    entry->conn->SetPeerMss(mss);
                    BindDataPath(id, *shard, entry->local, entry->remote, *entry->conn, true);
                    shard->conns_[id] = entry;
                    shard->FlowInsert(fh, key, shard->conns_[id]);
                    if (NULLPTR != accept_handler_ &&
                        !accept_handler_(id, shard->conns_[id]->remote, shard->conns_[id]->local)) {
                        shard->conns_[id]->conn->Abort();
                        shard->FlowErase(fh, key);
                        ReclaimMimtFlow(shard, id);
                        ReclaimQdiscFlow(id);
                        shard->slab_.FreeSlot(entry);  // see the MD5-reject site: erase must free the slot
                        shard->conns_.erase(id);
                        conn_count_.fetch_sub(1, std::memory_order_relaxed);
                        return;
                    }
                    // Deliver any data piggybacked on the cookie ACK and apply
                    // the ACK's advertised window. The rebuilt connection starts
                    // with snd_wnd_ = kDefaultWindow (TcpConn ctor) and the
                    // cookie ACK is the peer's only handshake segment, so its
                    // window must be applied here - otherwise a small-window
                    // client is flooded up to 64KB before the first data ACK
                    // corrects the window. kEstablished OnSegment applies it
                    // (SND.WL-guarded, mirror of tcp_fsm.cpp:4175-4191) for a pure
                    // ACK too; the segment carries piggyback data when present.
                    MarkSweep(*shard);  // new connection is born dirty; segment may arm ACK/RTO
                    if (ce_marked) {
                        shard->conns_[id]->conn->SetCeSeen();  // RFC 3168 s6.1.3: CE -> ECE echo
                    }
                    shard->conns_[id]->conn->OnSegment(data + tcp_off, len - tcp_off, GetTickUs());
                    MarkSweep(*shard);  // rebuilt connection is born dirty: retransmit may be armed
                    // Mirror the regular flow path: notify the app of the
                    // post-segment state. The rebuilt connection can close
                    // immediately (e.g. the peer RSTs instead of completing
                    // the cookie ACK exchange) - the app must see kClosed.
                    if (NULLPTR != state_handler_) {
                        state_handler_(id, shard->conns_[id]->conn->State());
                    }
                    return;  // slot held by the rebuilt connection
                }
                conn_count_.fetch_sub(1, std::memory_order_relaxed);  // not a valid cookie ACK: release the slot
                return;
            }
            return;
        }
        ConnEntry* entry = routed;
        if (NULLPTR == entry || NULLPTR == entry->conn) {
            return;
        }
        if (0 < len && NULLPTR != data) {
            MarkSweep(*shard);  // OnSegment may arm ACK/RTO/keepalive timers
            if (ce_marked) {
                entry->conn->SetCeSeen();  // RFC 3168 s6.1.3: CE -> ECE echo
            }
            entry->conn->OnSegment(data + tcp_off, len - tcp_off, GetTickUs());
        }
        if (NULLPTR != state_handler_) {
            state_handler_(entry->id, entry->conn->State());
        }
    }

    UInt32 XtcpStack::DeriveIss(const core::Endpoint& local, const core::Endpoint& remote) noexcept {
        // RFC 793 requires ISNs to be unpredictable so an off-path attacker
        // cannot guess sequence numbers.  The 4-tuple hash alone is
        // deterministic - a reconnect on the same 4-tuple would reuse the
        // same ISN, defeating the anti-spoofing property.  Mix in the
        // connection-creation time: DeriveIss is invoked exactly once per
        // connection, at TcpConn construction, and SYN retransmissions reuse
        // the stored iss_, so the ISN stays stable within a connection (the
        // retransmitted SYN carries the same seq) while a same-tuple
        // reconnect at a different time gets a different ISN.
        UInt32 iss = 0x40000000;
        iss += (local.addr[0] ^ remote.addr[0]) * 131;
        iss += (local.addr[1] ^ remote.addr[1]) * 193;
        iss += static_cast<UInt32>(local.port) * 17;
        iss += static_cast<UInt32>(remote.port) * 7;
        const UInt32 t = static_cast<UInt32>((GetTickUs() >> 12) * 0x9E3779B1u);
        iss += t * 0x9E3779B1u;  // Knuth multiplicative hash: spread the time bits
        return iss;
    }
}




