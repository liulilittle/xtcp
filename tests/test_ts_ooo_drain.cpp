/**
 * @file test_ts_ooo_drain.cpp
 * @brief RFC 7323 s4.3(C): echo the timestamp of the segment filling
 *        the hole, without replacing it with a cached OOO timestamp.
 *
 * After a live handshake, this test hand-builds two timestamped peer
 * data segments: segment 2 delivered out of order (buffered),
 * then segment 1 (in-order, drains segment 2). The receiver's ACK must
 * echo tsecr == segment 1's TSval. A subsequent stale segment must still
 * fail PAWS in established and closing states.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

namespace {

    struct TsInfo {
        bool  has = false;
        UInt32 ts_val = 0;
        UInt32 ts_ecr = 0;
    };

    TsInfo ParseTs(const Byte* pkt) {
        TsInfo out;
        if (NULLPTR == pkt) {
            return out;
        }
        const Byte* t = pkt + 20;
        const UInt32 data_off = (t[12] >> 4) * 4;
        UInt32 off = 20;
        while (off + 9 <= data_off) {
            const Byte kind = t[off];
            if (0 == kind) {
                break;
            }
            if (1 == kind) {
                ++off;
                continue;
            }
            const UInt32 len = t[off + 1];
            if (len < 2 || off + len > data_off) {
                break;
            }
            if (8 == kind && 10 == len) {
                out.has = true;
                out.ts_val = (static_cast<UInt32>(t[off + 2]) << 24) |
                             (static_cast<UInt32>(t[off + 3]) << 16) |
                             (static_cast<UInt32>(t[off + 4]) << 8) |
                             static_cast<UInt32>(t[off + 5]);
                out.ts_ecr = (static_cast<UInt32>(t[off + 6]) << 24) |
                             (static_cast<UInt32>(t[off + 7]) << 16) |
                             (static_cast<UInt32>(t[off + 8]) << 8) |
                             static_cast<UInt32>(t[off + 9]);
                break;
            }
            off += len;
        }
        return out;
    }

    UInt16 OnesChecksum(const Byte* data, UInt32 len, UInt32 seed) {
        UInt32 sum = seed;
        for (UInt32 i = 0; i + 1 < len; i += 2) {
            sum += static_cast<UInt32>((data[i] << 8) | data[i + 1]);
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        if (0 != (len & 1)) {
            sum += static_cast<UInt32>(data[len - 1] << 8);
        }
        while (0 != (sum >> 16)) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<UInt16>(~sum & 0xFFFF);
    }

    // Builds an IPv4+TCP data segment with a kind-8 TSopt. Returns the
    // frame in out (out_cap bytes). seq/ack/ts fields as given; payload
    // filled with 0x5E. IP src/dst/ports match the established connection.
    UInt32 BuildTsSegment(Byte* out, UInt32 out_cap, UInt32 seq, UInt32 ack,
                          UInt32 ts_val, UInt32 ts_ecr, UInt32 payload_len, Byte flags = 0x18) {
        const UInt32 tcp_hdr = 20 + 12;  // base + TSopt
        const UInt32 total = 20 + tcp_hdr + payload_len;
        if (out_cap < total) {
            return 0;
        }
        std::memset(out, 0, total);
        out[0] = 0x45;
        out[2] = static_cast<Byte>(total >> 8);
        out[3] = static_cast<Byte>(total & 0xFF);
        out[8] = 64;
        out[9] = 6;
        out[12] = 0xC0; out[13] = 0xA8; out[14] = 0x01; out[15] = 0x02;  // client
        out[16] = 0x0A; out[17] = 0x00; out[18] = 0x00; out[19] = 0x01;  // server
        Byte* t = out + 20;
        t[0] = 0x9C; t[1] = 0x40;  // sport 40000
        t[2] = 0x01; t[3] = 0xBB;  // dport 443
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = static_cast<Byte>(tcp_hdr / 4 << 4);  // data offset
        t[13] = flags;  // ACK|PSH by default; pure FIN uses ACK|FIN.
        t[14] = 0xFF; t[15] = 0xFF;  // window
        // TSopt (kind 8, len 10).
        t[20] = 8; t[21] = 10;
        t[22] = static_cast<Byte>(ts_val >> 24); t[23] = static_cast<Byte>(ts_val >> 16);
        t[24] = static_cast<Byte>(ts_val >> 8);  t[25] = static_cast<Byte>(ts_val & 0xFF);
        t[26] = static_cast<Byte>(ts_ecr >> 24); t[27] = static_cast<Byte>(ts_ecr >> 16);
        t[28] = static_cast<Byte>(ts_ecr >> 8);  t[29] = static_cast<Byte>(ts_ecr & 0xFF);
        std::memset(out + 20 + tcp_hdr, 0x5E, payload_len);
        // IPv4 checksum.
        out[10] = 0; out[11] = 0;
        const UInt16 ip_csum = OnesChecksum(out, 20, 0);
        out[10] = static_cast<Byte>(ip_csum >> 8);
        out[11] = static_cast<Byte>(ip_csum & 0xFF);
        // TCP checksum (pseudo-header + segment).
        UInt32 seed = 0;
        for (UInt32 i = 0; i < 8; i += 2) {
            seed += static_cast<UInt32>((out[12 + i] << 8) | out[13 + i]);
            while (0 != (seed >> 16)) {
                seed = (seed & 0xFFFF) + (seed >> 16);
            }
        }
        seed += 6u;  // protocol
        seed += static_cast<UInt32>(tcp_hdr + payload_len);
        while (0 != (seed >> 16)) {
            seed = (seed & 0xFFFF) + (seed >> 16);
        }
        t[16] = 0; t[17] = 0;
        const UInt16 tcp_csum = OnesChecksum(t, tcp_hdr + payload_len, seed);
        t[16] = static_cast<Byte>(tcp_csum >> 8);
        t[17] = static_cast<Byte>(tcp_csum & 0xFF);
        return total;
    }

}  // namespace

static void RunCase(bool closing) {
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        UInt64 server_conn = 0;
        stack_b.SetAcceptHandler([&](UInt64 id, const xtcp::core::Endpoint&, const xtcp::core::Endpoint&) {
            server_conn = id;
            return true;
        });
        std::atomic<UInt64> b_recv{0};
        stack_b.SetRecvHandlerChecked([&](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });

        // tsecr of every timestamped B->A segment. A gap-filling segment is
        // ACKed immediately, so pump() forwards that ACK before the caller
        // can poll B's queue; record it here.
        std::vector<UInt32> b_ecrs;
        UInt32 client_last_tsval = 0;
        bool client_tsval_seen = false;
        UInt32 client_ack = 0;
        UInt32 frontier = 0;
        bool probe_acked = false;
        bool synthetic_peer = false;
        auto pump = [&]() {
            Byte out[65536];
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    const Byte* t = out + 20;
                    client_ack = (UInt32(t[8]) << 24) | (UInt32(t[9]) << 16) |
                                 (UInt32(t[10]) << 8) | UInt32(t[11]);
                    const TsInfo ts = ParseTs(out);
                    if (ts.has) {
                        client_last_tsval = ts.ts_val;
                        client_tsval_seen = true;
                    }
                    backend_b.Inject(out, n, 0x0800);
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    if (b_recv.load() == 1) {
                        const Byte* t = out + 20;
                        frontier = (UInt32(t[8]) << 24) | (UInt32(t[9]) << 16) |
                                   (UInt32(t[10]) << 8) | UInt32(t[11]);
                        probe_acked = true;
                    }
                    const TsInfo ts = ParseTs(out);
                    if (ts.has) {
                        b_ecrs.push_back(ts.ts_ecr);
                    }
                    if (!synthetic_peer) backend_a.Inject(out, n, 0x0800);
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint server_ep, client_ep;
        server_ep.family = 4;
        server_ep.addr[0] = 0x0A000001;
        server_ep.port = 443;
        client_ep.family = 4;
        client_ep.addr[0] = 0xC0A80102;
        client_ep.port = 40000;
        CHECK(stack_b.Listen(server_ep));

        const UInt64 conn = stack_a.Connect(client_ep, server_ep);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Learn the receive frontier: send 1 byte; the server's ACK's ack
        // field is rcv_nxt.
        const Byte one = 0x01;
        CHECK(stack_a.Send(conn, &one, 1));
        for (UInt32 i = 0; i < 200 && !probe_acked; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(probe_acked);
        CHECK(server_conn != 0);
        if (!probe_acked || !server_conn) return;
        std::fprintf(stderr, "[ts-ooo-drain] frontier=%08X\n", frontier);
        if (closing) {
            stack_b.Close(server_conn);
            for (unsigned i = 0; i < 20; ++i) pump();
            CHECK(stack_b.ConnectionState(server_conn) == xtcp::core::TcpState::kFinWait2);
        }
        synthetic_peer = true;

        // Segment 2 (seq = frontier + 1460) delivered FIRST: buffered as
        // out-of-order, nothing reaches the app.
        const UInt32 kPayload = 1460;
        CHECK(client_tsval_seen);
        // Keep synthetic peer timestamps newer than the actual handshake and
        // probe timestamps so PAWS does not discard the test data on hosts
        // whose monotonic clock has already passed the old fixed TSval.
        // The hole is filled by a newer retransmission. Draining the older
        // cached segment must neither change the echo nor lower PAWS.
        const UInt32 kTs1 = client_last_tsval + 3;
        const UInt32 kTs2 = client_last_tsval + 2;
        Byte frame[2048];
        const UInt32 n2 = BuildTsSegment(frame, sizeof(frame), frontier + kPayload,
                                         client_ack, kTs2, 0, kPayload);
        CHECK(0 != n2);
        {
            xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(n2);
            std::memcpy(b.Data(), frame, n2);
            b.SetLen(n2);
            xtcp::ndi::Packet p;
            p.data = b.Data();
            p.len = n2;
            p.owned = std::move(b);
            backend_b.Inject(std::move(p));
            pump();
        }
        CHECK(1 == b_recv.load());  // only the 1-byte probe; OOO segment buffered

        // Segment 1 (seq = frontier): in-order; the app receives both
        // (segment 2 via the drain). The echo must retain kTs1.
        b_ecrs.clear();
        const UInt32 n1 = BuildTsSegment(frame, sizeof(frame), frontier, client_ack, kTs1, 0, kPayload);
        CHECK(0 != n1);
        {
            xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(n1);
            std::memcpy(b.Data(), frame, n1);
            b.SetLen(n1);
            xtcp::ndi::Packet p;
            p.data = b.Data();
            p.len = n1;
            p.owned = std::move(b);
            backend_b.Inject(std::move(p));
            pump();
        }
        CHECK(1 + 2 * kPayload == b_recv.load());  // probe + both segments delivered

        // The server's first ACK after the drain must echo tsecr == kTs1.
        // A delayed ACK needs real
        // time, so keep pumping until one is observed.
        UInt32 ack_ecr = 0;
        bool ack_seen = false;
        for (UInt32 i = 0; i < 300 && !ack_seen; ++i) {
            if (!b_ecrs.empty()) {
                ack_ecr = b_ecrs.front();
                ack_seen = true;
                break;
            }
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(ack_seen);
        std::fprintf(stderr, "[ts-ooo-drain] closing=%d ACK tsecr=%08X expected=%08X\n", closing, ack_ecr, kTs1);
        CHECK(ack_ecr == kTs1);
        auto inject = [&](UInt32 ts) {
            const UInt32 n = BuildTsSegment(frame, sizeof(frame), frontier + 2 * kPayload,
                                            client_ack, ts, 0, 1);
            backend_b.Inject(frame, n, 0x0800);
            pump();
        };
        inject(kTs2);  // Older than the gap-filler: must fail PAWS.
        CHECK(b_recv.load() == 1 + 2 * kPayload);
        inject(kTs1 + 1);
        CHECK(b_recv.load() == 2 + 2 * kPayload);
        auto inject_fin = [&](UInt32 ts) {
            const UInt32 n = BuildTsSegment(frame, sizeof(frame), frontier + 2 * kPayload + 1,
                                            client_ack, ts, 0, 0, 0x11);
            CHECK(n != 0);
            backend_b.Inject(frame, n, 0x0800);
            pump();
        };
        const auto before_fin = stack_b.ConnectionState(server_conn);
        inject_fin(kTs2);
        CHECK(stack_b.ConnectionState(server_conn) == before_fin);
        b_ecrs.clear();
        inject_fin(kTs1 + 2);
        CHECK(stack_b.ConnectionState(server_conn) == (closing
            ? xtcp::core::TcpState::kTimeWait : xtcp::core::TcpState::kCloseWait));
        CHECK(!b_ecrs.empty());
        if (!b_ecrs.empty()) CHECK(b_ecrs.back() == kTs1 + 2);
    }
}

int main() {
    xtcp::buf::InitPools();
    for (bool closing : {false, true}) {
        RunCase(closing);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TS_OOO_DRAIN: FAILED (%d)\n" : "TS_OOO_DRAIN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}
