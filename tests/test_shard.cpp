/**
 * @file test_shard.cpp
 * @brief Shard tests: flow table add/lookup/remove, churn, family isolation.
 */

#include <xtcp/core/shard.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstdlib>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static xtcp::core::FlowKey MakeKey(UInt32 family, UInt32 src, UInt32 dst, UInt16 sport, UInt16 dport) noexcept {
    xtcp::core::FlowKey key;
    key.addr_family = static_cast<Byte>(family);
    key.saddr[0] = src;
    key.daddr[0] = dst;
    key.sport = sport;
    key.dport = dport;
    return key;
}

static void TestAddLookupRemove() {
    xtcp::core::Shard shard(1024, 64);
    const xtcp::core::FlowKey key = MakeKey(4, 0xC0A80101, 0x0A000002, 443, 50000);

    CHECK(0 == shard.Lookup(key));
    CHECK(shard.AddFlow(key, 42));
    CHECK(42 == shard.Lookup(key));
    CHECK(1 == shard.FlowCount());

    // Duplicate add is rejected.
    CHECK(!shard.AddFlow(key, 43));
    CHECK(42 == shard.Lookup(key));

    CHECK(shard.RemoveFlow(key));
    CHECK(0 == shard.Lookup(key));
    CHECK(0 == shard.FlowCount());
    CHECK(!shard.RemoveFlow(key));  // absent
}

static void TestChurn100k() {
    xtcp::core::Shard shard(1024, 64);
    // Insert 100k flows, verify all resolvable.
    for (UInt32 i = 1; i <= 100000; ++i) {
        const xtcp::core::FlowKey key = MakeKey(4, i, i + 1, static_cast<UInt16>(i & 0xFFFF), 80);
        CHECK(shard.AddFlow(key, i));
    }
    CHECK(100000 == shard.FlowCount());
    for (UInt32 i = 1; i <= 100000; ++i) {
        const xtcp::core::FlowKey key = MakeKey(4, i, i + 1, static_cast<UInt16>(i & 0xFFFF), 80);
        CHECK(i == shard.Lookup(key));
    }
    // Remove half, verify the rest survive.
    for (UInt32 i = 1; i <= 100000; i += 2) {
        const xtcp::core::FlowKey key = MakeKey(4, i, i + 1, static_cast<UInt16>(i & 0xFFFF), 80);
        CHECK(shard.RemoveFlow(key));
    }
    CHECK(50000 == shard.FlowCount());
    for (UInt32 i = 2; i <= 100000; i += 2) {
        const xtcp::core::FlowKey key = MakeKey(4, i, i + 1, static_cast<UInt16>(i & 0xFFFF), 80);
        CHECK(i == shard.Lookup(key));
    }
    for (UInt32 i = 1; i <= 100000; i += 2) {
        const xtcp::core::FlowKey key = MakeKey(4, i, i + 1, static_cast<UInt16>(i & 0xFFFF), 80);
        CHECK(0 == shard.Lookup(key));
    }
}

static void TestFamilyIsolation() {
    xtcp::core::Shard shard(256, 64);
    // Same numeric addresses, different family.
    const xtcp::core::FlowKey v4 = MakeKey(4, 0xC0A80101, 0x0A000002, 443, 50000);
    const xtcp::core::FlowKey v6 = MakeKey(6, 0xC0A80101, 0x0A000002, 443, 50000);

    CHECK(shard.AddFlow(v4, 1));
    CHECK(shard.AddFlow(v6, 2));
    CHECK(1 == shard.Lookup(v4));
    CHECK(2 == shard.Lookup(v6));
    CHECK(2 == shard.FlowCount());
}

static void TestPoolAndTimers() {
    xtcp::core::Shard shard(256, 32);
    void* block = shard.Pool().Alloc();
    CHECK(NULLPTR != block);
    shard.Pool().Free(block);

    bool fired = false;
    shard.Timers().Add(1000, [&]() { fired = true; });
    CHECK(0 == shard.AdvanceTime(999));
    CHECK(!fired);
    CHECK(1 == shard.AdvanceTime(1000));
    CHECK(fired);
}

static void TestOutgoingPacketShard() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        for (Byte family : {Byte(4), Byte(6)}) {
            for (UInt16 i = 0; i < 64; ++i) {
                xtcp::core::Endpoint local, remote;
                local.family = remote.family = family;
                local.addr[0] = family == 4 ? 0xC0A80102 : 0x20010DB8;
                remote.addr[0] = family == 4 ? 0x0A000001 : 0x20010DB8;
                if (family == 6) {
                    local.addr[3] = 1 + i;
                    remote.addr[3] = 1000 + i;
                }
                local.port = 40000 + i;
                remote.port = 443;
                const UInt64 id = stack.Connect(local, remote);
                CHECK(id != 0);
                Byte bytes[256];
                xtcp::ndi::Packet packet;
                packet.data = bytes;
                packet.len = backend.PollTx(bytes);
                CHECK(packet.len >= 40);
                // TX source is local; reversing the tuple selects the
                // receiver's shard and misattributes DMA/qdisc retries.
                if (packet.len >= 40) CHECK(stack.ShardOfPacket(packet) == stack.ShardOf(id));
            }
        }
    }
    xtcp::buf::ShutdownPools();
}

int main() {
    TestAddLookupRemove();
    TestChurn100k();
    TestFamilyIsolation();
    TestPoolAndTimers();
    TestOutgoingPacketShard();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_shard: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_shard: all passed\n");
    return 0;
}
