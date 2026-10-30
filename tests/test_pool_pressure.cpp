/**
 * @file test_pool_pressure.cpp
 * @brief Global packet-pool pressure must not wedge ACK ingress.
 *
 * Regression for the OpenPPP2 P64 wedge: when active flows x snd_buf
 * exceeded the fixed arena, unACKed transmit segments held every block,
 * ingress (including the pure ACKs that would release them) could not
 * allocate and was dropped, and nothing ever freed the pool again.
 *
 *  - tx_reserve: TxAcquireScope acquisitions stop at the tier reserve, so
 *    ordinary (ingress/ACK) acquisitions still succeed afterwards.
 *  - heap_overflow: with every tier empty, ordinary acquisitions are served
 *    by the bounded heap overflow, deny at the cap, and give every byte
 *    back on release.
 *  - conn_wedge: many established connections queue far more retained send
 *    data than the arena holds; transmit stops at the reserve (data stays
 *    buffered), an ACK segment can still be allocated, delivered ACKs drain
 *    the retransmission queues, buffered data flows again and every flow
 *    finishes - no deadlock.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/tcp.h>
#include <xtcp/cc/cc.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace {
using namespace xtcp::core;
int failures = 0;
#define CHECK(x) do { if (!(x)) { ++failures; std::fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); } } while (0)

void Put32(Byte* p, UInt32 n) {
    p[0] = Byte(n >> 24); p[1] = Byte(n >> 16);
    p[2] = Byte(n >> 8); p[3] = Byte(n);
}

UInt64 Now() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

Endpoint EndpointAt(UInt32 ip, UInt16 port) {
    Endpoint e; e.family = 4; e.addr[0] = ip; e.port = port; return e;
}

void TxReserve() {
    const auto before = xtcp::buf::GetPoolPressureStats();
    std::vector<xtcp::buf::BufRef> tx;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            tx.push_back(std::move(ref));
        }
    }
    const auto after = xtcp::buf::GetPoolPressureStats();
    CHECK(!tx.empty());
    CHECK(after.tx_deferrals > before.tx_deferrals);
    CHECK(after.heap_overflow_acquires == before.heap_overflow_acquires);
    // The reserve (1/8 of every fitting tier) is still there for ingress.
    std::vector<xtcp::buf::BufRef> rx;
    for (unsigned i = 0; i < 512; ++i) {
        auto ref = xtcp::buf::BufRef::Acquire(60);
        CHECK(!ref.IsEmpty());
        rx.push_back(std::move(ref));
    }
    const auto end = xtcp::buf::GetPoolPressureStats();
    CHECK(end.heap_overflow_acquires == before.heap_overflow_acquires);
    std::printf("tx_reserve: tx_blocks=%zu rx_blocks=%zu deferrals=%llu\n", tx.size(), rx.size(),
        static_cast<unsigned long long>(after.tx_deferrals - before.tx_deferrals));
}

void HeapOverflow() {
    std::vector<xtcp::buf::BufRef> held;
    for (;;) {
        auto ref = xtcp::buf::BufRef::Acquire(60);
        if (ref.IsEmpty()) break;
        held.push_back(std::move(ref));
    }
    const auto full = xtcp::buf::GetPoolPressureStats();
    CHECK(full.heap_overflow_acquires > 0);
    CHECK(full.heap_overflow_denials > 0);
    CHECK(full.heap_overflow_bytes <= xtcp::buf::kHeapOverflowCapBytes);
    CHECK(full.heap_overflow_bytes + 2048 > xtcp::buf::kHeapOverflowCapBytes);
    {
        // Transmit data never takes heap overflow.
        xtcp::buf::TxAcquireScope scope;
        CHECK(xtcp::buf::BufRef::Acquire(60).IsEmpty());
    }
    held.clear();
    const auto drained = xtcp::buf::GetPoolPressureStats();
    CHECK(drained.heap_overflow_bytes == 0);
    CHECK(!xtcp::buf::BufRef::Acquire(60).IsEmpty());
    std::printf("heap_overflow: blocks=%zu peak=%llu\n", held.capacity(),
        static_cast<unsigned long long>(full.heap_overflow_peak));
}

struct Flow {
    std::unique_ptr<TcpConn> conn;
    UInt32 sent = 0;
};

void Ack(TcpConn& c, UInt32 ack, UInt64 now, UInt16 window = 0xffff) {
    Byte p[20] = {};
    p[0] = 0x07; p[1] = 0xd1; p[2] = 0x03; p[3] = 0xe9;
    Put32(p + 4, 201); Put32(p + 8, ack);
    p[12] = 0x50; p[13] = Byte(kFlagAck);
    p[14] = Byte(window >> 8); p[15] = Byte(window);
    c.OnSegment(p, sizeof(p), now);
}

void ConnWedge() {
    constexpr unsigned kFlows = 1600;
    constexpr UInt32 kTotal = 256 * 1024;
    constexpr UInt32 kChunk = 16 * 1024;
    std::vector<Byte> chunk(kChunk, 0x5a);
    std::vector<Flow> flows(kFlows);
    UInt64 now = Now();
    for (unsigned i = 0; i < kFlows; ++i) {
        flows[i].conn.reset(new TcpConn(TcpState::kEstablished, EndpointAt(0x0a000001, 1001),
            EndpointAt(0x0a000002, 2001), 100, 200, [](xtcp::buf::BufRef&&) {}));
        flows[i].conn->SetNodelay(true);
        flows[i].conn->SetSndBuf(kTotal);
        Ack(*flows[i].conn, flows[i].conn->SndNxt(), now);  // open the peer window
    }
    const auto before = xtcp::buf::GetPoolPressureStats();
    auto pump = [&](Flow& f) {
        while (f.sent < kTotal && f.conn->SendData(chunk.data(), kChunk, now)) f.sent += kChunk;
    };
    for (auto& f : flows) pump(f);
    // Buffered ranges are emitted by the poll flush (ACK-clock refill);
    // grow cwnd with a few full ACK rounds first so retention exceeds the arena.
    for (unsigned r = 0; r < 6; ++r) {
        now += 1000;
        for (auto& f : flows) {
            f.conn->OnPoll(now);
            if (r < 5 && f.conn->SndUna() != f.conn->SndNxt()) Ack(*f.conn, f.conn->SndNxt(), now);
            pump(f);
        }
    }
    const auto loaded = xtcp::buf::GetPoolPressureStats();
    // Transmit retention hit the reserve: deferrals, no heap overflow use.
    CHECK(loaded.tx_deferrals > before.tx_deferrals);
    CHECK(loaded.heap_overflow_acquires == before.heap_overflow_acquires);
    // An ingress ACK buffer is still available from the pool reserve.
    CHECK(!xtcp::buf::BufRef::Acquire(60).IsEmpty());
    unsigned buffered = 0;
    for (auto& f : flows) if (0 < f.conn->PendingSendBytes()) ++buffered;
    CHECK(buffered > 0);

    // Age genuinely blocked senders while unrelated retransmission queues
    // still own the arena; the following drain exercises a large FIFO.
    for (unsigned r = 0; r < 128; ++r) {
        now += 1000;
        for (auto& f : flows) f.conn->OnPoll(now);
    }

    // Drive ACKs + polls until every flow has delivered everything.
    unsigned rounds = 0;
    bool done = false;
    for (; rounds < 4000 && !done; ++rounds) {
        now += 1000;
        done = true;
        for (auto& f : flows) {
            if (f.conn->SndUna() != f.conn->SndNxt()) Ack(*f.conn, f.conn->SndNxt(), now);
            f.conn->OnPoll(now);
            pump(f);
            if (f.sent < kTotal || 0 < f.conn->PendingSendBytes() ||
                f.conn->SndUna() != f.conn->SndNxt()) done = false;
        }
    }
    CHECK(done);
    const auto end = xtcp::buf::GetPoolPressureStats();
    CHECK(end.heap_overflow_bytes == 0);
    std::printf("conn_wedge: flows=%u buffered_at_peak=%u rounds=%u deferrals=%llu heap_acq=%llu\n",
        kFlows, buffered, rounds,
        static_cast<unsigned long long>(end.tx_deferrals - before.tx_deferrals),
        static_cast<unsigned long long>(end.heap_overflow_acquires - before.heap_overflow_acquires));
}

void PoolReleaseWithoutOwnAck() {
    xtcp::ndi::ManualBackend a, b;
    xtcp::XtcpStack sender(&a), receiver(&b);
    auto wire = [](xtcp::ndi::ManualBackend& backend, xtcp::XtcpStack& stack) {
        backend.SetRxHandler([&stack](xtcp::ndi::Packet&& packet) {
            auto ref = xtcp::buf::BufRef::Acquire(packet.len);
            CHECK(!ref.IsEmpty());
            if (ref.IsEmpty()) return;
            std::memcpy(ref.Data(), packet.data, packet.len);
            ref.SetLen(packet.len);
            stack.OnPacket(std::move(ref));
        });
    };
    wire(a, sender);
    wire(b, receiver);
    auto pump = [](xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
        Byte packet[65536];
        while (from.TxPending()) {
            const UInt32 size = from.PollTx(packet);
            if (!size) break;
            to.Inject(packet, size, 0x0800);
        }
    };
    const auto local = EndpointAt(0x0a000001, 1001);
    const auto remote = EndpointAt(0x0a000002, 2001);
    CHECK(receiver.Listen(remote));
    UInt32 received = 0;
    receiver.SetRecvHandler([&](UInt64, const Byte* data, UInt32 size) {
        for (UInt32 i = 0; i < size; ++i) CHECK(data[i] == 0x5a);
        received += size;
    });
    const UInt64 conn = sender.Connect(local, remote);
    CHECK(conn != 0);
    pump(a, b); pump(b, a); pump(a, b);

    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    std::vector<Byte> data(16 * 1024, 0x5a);
    const auto before = xtcp::buf::GetPoolPressureStats();
    CHECK(sender.Send(conn, data.data(), static_cast<UInt32>(data.size())));
    sender.PollAckTimers();
    CHECK(a.TxPending() == 0);
    CHECK(xtcp::buf::GetPoolPressureStats().tx_deferrals > before.tx_deferrals);
    // This connection has never emitted data: no ACK/RTO can restart it.
    retained.clear();
    sender.PollAckTimers();
    CHECK(a.TxPending() > 0);
    for (unsigned i = 0; i < 1000 && received < data.size(); ++i) {
        pump(a, b); pump(b, a);
        sender.PollAckTimers(); receiver.PollAckTimers();
    }
    CHECK(received == data.size());
    std::printf("pool_release_without_own_ack: received=%u\n", received);
}

void AgeWaiter(xtcp::buf::TxWaiter& waiter, UInt32 size) {
    for (unsigned i = 0; i < 1024; ++i) {
        xtcp::buf::TxAcquireScope scope(&waiter);
        CHECK(xtcp::buf::BufRef::Acquire(size).IsEmpty());
    }
}

void PoolDelayIsNotNetworkRate() {
    xtcp::cc::RegisterKcc();
    std::vector<xtcp::buf::BufRef> wire;
    TcpConn conn(TcpState::kEstablished, EndpointAt(0x0a000001, 1001),
        EndpointAt(0x0a000002, 2001), 100, 200,
        [&](xtcp::buf::BufRef&& ref) { wire.push_back(std::move(ref)); });
    CHECK(conn.SetCongestionControl("kcc"));
    conn.SetNodelay(true);
    conn.SetSndBuf(256 * 1024);
    UInt64 now = Now();
    Ack(conn, conn.SndNxt(), now);
    Byte small[128] = {};
    for (unsigned i = 0; i < 2; ++i) {
        now += 1000;
        CHECK(conn.SendData(small, sizeof(small), now));
        Ack(conn, conn.SndNxt(), now + 500);
        wire.clear();
    }
    std::vector<Byte> data(256 * 1024, 0x5a);
    now += 1000;
    CHECK(conn.SendData(data.data(), static_cast<UInt32>(data.size()), now));
    conn.OnPoll(now);
    // Upstream paces one segment per tick; retain two before exhausting the
    // pool so a partial ACK leaves a live ACK clock. No burst-pacing patch.
    now += 100000;
    conn.OnPoll(now);
    now += 100000;
    CHECK(conn.PendingSendBytes() > 0);
    CHECK(conn.SndNxt() != conn.SndUna());
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    // The wire still holds the ACKed packets, so the ACK drains the pipe
    // without releasing arena blocks. Queued application data is unchanged.
    Ack(conn, conn.SndUna() + conn.PeerMss(), now + 500);
    const UInt32 remaining = conn.SndNxt() - conn.SndUna();
    CHECK(remaining > 0);
    CHECK(conn.AppLimitedMarker() == 0);  // brief pressure with a live ACK clock
    for (unsigned i = 0; i < 1024; ++i) conn.OnPoll(now + 500);
    CHECK(conn.AppLimitedMarker() == static_cast<UInt32>(conn.DeliveredPkts()) +
        (remaining + conn.PeerMss() - 1) / conn.PeerMss());
    Ack(conn, conn.SndNxt(), now + 1000);
    CHECK(conn.SndNxt() == conn.SndUna());
    CHECK(conn.PendingSendBytes() > 0);
    CHECK(conn.AppLimitedMarker() != 0);
    CHECK(conn.AppLimitedMarker() == static_cast<UInt32>(conn.DeliveredPkts()));
    std::printf("pool_rate_sample: marker=%u delivered=%llu pending=%u\n",
        conn.AppLimitedMarker(), static_cast<unsigned long long>(conn.DeliveredPkts()),
        conn.PendingSendBytes());
    now += 100000;
    CHECK(conn.PacingRate() > 0);
    conn.OnPoll(now);  // allocation fails after the pacing clock opens
    CHECK(conn.SndNxt() == conn.SndUna());
    retained.pop_back();
    conn.OnPoll(now);  // no elapsed wire time and no data ACK
    CHECK(conn.SndNxt() != conn.SndUna());
}

void AgeConn(TcpConn& conn, UInt64& now) {
    for (unsigned i = 0; i < 1024; ++i) {
        now += 1000;
        conn.OnPoll(now);
    }
}

void TransientPressureKeepsExistingAdmission() {
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    xtcp::buf::TxWaiter recent, busy;
    {
        xtcp::buf::TxAcquireScope scope(&recent);
        CHECK(xtcp::buf::BufRef::Acquire(1500).IsEmpty());
    }
    retained.pop_back();
    xtcp::buf::BufRef ref;
    {
        xtcp::buf::TxAcquireScope scope(&busy);
        ref = xtcp::buf::BufRef::Acquire(1500);
        CHECK(!ref.IsEmpty());
    }
    ref = xtcp::buf::BufRef();
    {
        xtcp::buf::TxAcquireScope scope(&recent);
        CHECK(!xtcp::buf::BufRef::Acquire(1500).IsEmpty());
    }
}

void DeferredConnCannotBeOvertaken() {
    UInt32 emitted = 0;
    TcpConn waiting(TcpState::kEstablished, EndpointAt(0x0a000001, 1001),
        EndpointAt(0x0a000002, 2001), 100, 200,
        [&](xtcp::buf::BufRef&&) { ++emitted; });
    TcpConn busy(TcpState::kEstablished, EndpointAt(0x0a000001, 1001),
        EndpointAt(0x0a000002, 2001), 100, 200, [](xtcp::buf::BufRef&&) {});
    UInt64 now = Now();
    waiting.SetNodelay(true); busy.SetNodelay(true);
    Ack(waiting, waiting.SndNxt(), now); Ack(busy, busy.SndNxt(), now);
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    Byte data[128] = {};
    CHECK(waiting.SendData(data, sizeof(data), now));
    CHECK(waiting.PendingSendBytes() == sizeof(data));
    CHECK(waiting.SndNxt() == waiting.SndUna());
    AgeConn(waiting, now);
    CHECK(!retained.empty());
    // Only one TX block becomes available. A busy ACK-clocked connection
    // gets the first callback, but must not steal the waiter's opportunity.
    retained.pop_back();
    now += 1000;
    CHECK(busy.SendData(data, sizeof(data), now));
    waiting.OnPoll(now);
    CHECK(emitted == 1);
    CHECK(waiting.PendingSendBytes() == 0);
}

void WaiterSizesAndCancellation() {
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    xtcp::buf::TxWaiter large, small;
    AgeWaiter(large, 20000);
    AgeWaiter(small, 100);
    CHECK(retained.size() > 32);
    retained.erase(retained.begin(), retained.begin() + 32);
    {
        // The older large waiter cannot use these small-tier releases.
        xtcp::buf::TxAcquireScope scope(&small);
        CHECK(!xtcp::buf::BufRef::Acquire(100).IsEmpty());
    }
    // Closing a deferred connection must remove its intrusive queue entry.
    large.Cancel();
    large.Cancel();
    retained.clear();
    {
        xtcp::buf::TxAcquireScope scope(&large);
        CHECK(!xtcp::buf::BufRef::Acquire(20000).IsEmpty());
    }
    CHECK(xtcp::buf::GetPoolPressureStats().heap_overflow_bytes == 0);
}

void WaiterOrderAndReservedCancellation() {
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    std::vector<std::unique_ptr<xtcp::buf::TxWaiter>> waiters;
    for (unsigned i = 0; i < 4; ++i) {
        waiters.emplace_back(new xtcp::buf::TxWaiter);
        AgeWaiter(*waiters.back(), 1500);
    }
    xtcp::buf::TxWaiter busy;
    retained.pop_back();
    for (auto& waiter : waiters) {
        {
            xtcp::buf::TxAcquireScope scope(&busy);
            CHECK(xtcp::buf::BufRef::Acquire(1500).IsEmpty());
        }
        // Destroy the first waiter while it owns its reserved block, then
        // consume the others in queue order. Each release unlocks the next.
        if (&waiter == &waiters.front()) {
            waiter.reset();
        } else {
            xtcp::buf::TxAcquireScope scope(waiter.get());
            CHECK(!xtcp::buf::BufRef::Acquire(1500).IsEmpty());
        }
    }
    {
        xtcp::buf::TxAcquireScope scope(&busy);
        CHECK(!xtcp::buf::BufRef::Acquire(1500).IsEmpty());
    }
}

void WindowStopPreservesOneGrant() {
    TcpConn waiting(TcpState::kEstablished, EndpointAt(0x0a000001, 1001),
        EndpointAt(0x0a000002, 2001), 100, 200, [](xtcp::buf::BufRef&&) {});
    waiting.SetNodelay(true);
    UInt64 now = Now();
    Ack(waiting, waiting.SndNxt(), now, 1024);
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    std::vector<Byte> data(32 * 1024, 0x5a);
    CHECK(waiting.SendData(data.data(), static_cast<UInt32>(data.size()), now));
    waiting.OnPoll(now);
    CHECK(waiting.SndNxt() == waiting.SndUna());
    AgeConn(waiting, now);
    CHECK(retained.size() > 32);
    retained.resize(retained.size() - 32);
    xtcp::buf::TxWaiter busy;
    {
        xtcp::buf::TxAcquireScope scope(&busy);
        CHECK(xtcp::buf::BufRef::Acquire(1500).IsEmpty());
    }
    Ack(waiting, waiting.SndUna(), now + 1000, 0);
    CHECK(waiting.SndNxt() == waiting.SndUna());
    CHECK(waiting.PendingSendBytes() > 0);
    std::vector<xtcp::buf::BufRef> busy_held;
    {
        xtcp::buf::TxAcquireScope scope(&busy);
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            busy_held.push_back(std::move(ref));
        }
    }
    CHECK(busy_held.size() >= 16);
    // With no arena space or data ACK, the one retained grant must let the
    // aged connection progress as soon as its peer window opens again.
    Ack(waiting, waiting.SndUna(), now + 2000, 1024);
    waiting.OnPoll(now + 3000);
    CHECK(waiting.SndNxt() - waiting.SndUna() == 1024);
}

void ConcurrentGrantPublication() {
    std::vector<xtcp::buf::BufRef> retained;
    {
        xtcp::buf::TxAcquireScope scope;
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(1500);
            if (ref.IsEmpty()) break;
            retained.push_back(std::move(ref));
        }
    }
    constexpr unsigned count = 8;
    std::atomic<unsigned> ready{0};
    std::atomic<bool> start{false};
    std::array<unsigned, count> successes{};
    std::vector<std::thread> workers;
    for (unsigned id = 0; id < count; ++id) {
        workers.emplace_back([&, id]() {
            xtcp::buf::TxWaiter waiter;
            for (unsigned i = 0; i < 1024; ++i) {
                xtcp::buf::TxAcquireScope scope(&waiter);
                auto ref = xtcp::buf::BufRef::Acquire(1500);
            }
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
            for (unsigned i = 0; i < 2048; ++i) {
                xtcp::buf::TxAcquireScope scope(&waiter);
                auto ref = xtcp::buf::BufRef::Acquire(1500);
                if (!ref.IsEmpty()) ++successes[id];
                if (0 == i % 32) waiter.ReleaseUnused();
            }
        });
    }
    while (ready.load(std::memory_order_acquire) != count) std::this_thread::yield();
    CHECK(retained.size() > 512);
    retained.resize(retained.size() - 512);
    start.store(true, std::memory_order_release);
    xtcp::buf::TxWaiter busy;
    for (unsigned i = 0; i < 2048; ++i) {
        xtcp::buf::TxAcquireScope scope(&busy);
        auto ref = xtcp::buf::BufRef::Acquire(1500);
        std::this_thread::yield();
    }
    for (auto& worker : workers) worker.join();
    for (unsigned n : successes) CHECK(n > 0);
}
} // namespace

int main() {
    xtcp::buf::InitPools();
    TxReserve();
    HeapOverflow();
    ConnWedge();
    PoolReleaseWithoutOwnAck();
    PoolDelayIsNotNetworkRate();
    TransientPressureKeepsExistingAdmission();
    DeferredConnCannotBeOvertaken();
    WaiterSizesAndCancellation();
    WaiterOrderAndReservedCancellation();
    WindowStopPreservesOneGrant();
    ConcurrentGrantPublication();
    xtcp::buf::ShutdownPools();
    return failures ? 1 : 0;
}
