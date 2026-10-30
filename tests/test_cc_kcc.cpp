/**
 * @file test_cc_kcc.cpp
 * @brief KCC fidelity differential vs the reference core
 *        (plugins/ref/kcc_core.c) plus white-box tests of the c8bead4
 *        estimator/min_rtt/cycle/full-bw fixes through the read-only
 *        KccSnapshot probe.
 *
 * Goldens marked "kcc_model" come from F:\kcc\tests\kcc_model.py
 * (read-only reference model at commit c8bead4).
 */

#include <xtcp/cc/cc.h>

#include "cc_kcc_probe.h"

#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include "ref/kcc_core.c"
}

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

namespace {
    using xtcp::cc::KccSnapshot;
    using xtcp::cc::RateSample;
    using xtcp::cc::XtcpConnCc;
    using xtcp::cc::XtcpCongestionOps;

    constexpr UInt32 kMss = 1460;
    constexpr UInt32 kDelivered = 29200;
    // Packet-domain pins (kernel bw = delivered_pkts << 24 / interval_us).
    // Driver input 29200 B / 20000 us = 20 segments -> bw = (20<<24)/20000
    // = 16777; rate = Haircut(MulShr8(bw*mss, gain)).
    constexpr UInt64 kStartupRate = 4172409;     /* gain 739 (2.887x) */
    constexpr UInt64 kProbeRate = 1806726;       /* gain 320 (1.25x) */
    constexpr UInt64 kDrainRate = 1084036;       /* 0.75x PROBE phase */
    constexpr UInt64 kDrainModeRate = 496849;    /* DRAIN mode (~0.347x) */
    constexpr UInt64 kCruiseRate = 1445381;      /* gain 256 (1.0x) */
    constexpr UInt64 kPacingExtreme = 1068150599751ull;

    /**
     * @brief Drives the port and the reference core with one shared input.
     *
     * Round cadence is DELIVERED-based now: Round() passes the pre-ACK
     * delivered total as prior_delivered, which crosses the next round
     * boundary exactly once. InRound() passes prior_delivered = 0, so it
     * stays inside the same burst (only the very first sample can open a
     * round). Tests that need an explicit boundary call Ack() with the
     * desired prior value.
     */
    struct Driver {
        kcc_core ref;
        XtcpConnCc sk;
        const XtcpCongestionOps* ops = NULLPTR;
        UInt64 now_us = 0;
        UInt32 last_rtt = 0;
        bool started = false;
        UInt32 flight = 20 * kMss;
        UInt64 total = 0;          /**< cc_.delivered equivalent (bytes) */
        UInt64 total_pkts = 0;     /**< cc_.delivered_pkts equivalent (segments) */
        UInt32 rand_seed = 2;      /**< must match KccTestSetRandomSeed(seed) */
        UInt32 edt_us = 0;         /**< kernel interval_to_edt fed to both sides */

        explicit Driver(UInt32 seed_min = 0, UInt32 srtt = 0, UInt32 rand_seed_ = 2)
            : rand_seed(rand_seed_) {
            std::memset(&ref, 0, sizeof(ref));
            kcc_core_init(&ref);
            ref.mss = kMss;
            ref.srtt_us = srtt;
            if (0 < seed_min) {
                ref.min_rtt_us = seed_min;
            } else if (0 < srtt) {
                ref.min_rtt_us = srtt;
            }
            kcc_core_set_random_seed(&ref, rand_seed);

            sk.mss = kMss;
            sk.rtt_min_us = seed_min;
            sk.srtt_us = srtt;
            sk.inflight = flight;
            ops = xtcp::cc::FindCongestionControl("kcc");
            CHECK(NULLPTR != ops);
            if (NULLPTR != ops) {
                ops->init(&sk);
            }
        }

        ~Driver() {
            if (NULLPTR != ops) {
                ops->release(&sk);
            }
        }

        KccSnapshot Snap() const {
            KccSnapshot snapshot;
            const bool ok = xtcp::cc::KccGetSnapshot(&sk, &snapshot);
            CHECK(ok);
            return snapshot;
        }

        void Ack(UInt32 rtt_us, UInt32 interval_us, UInt32 delivered = kDelivered,
                 UInt32 lost = 0, UInt64 prior_delivered = 0,
                 bool is_ack_delayed = false, bool is_app_limited = false) {
            // Packet domain (kernel tp->delivered counts tcp_skb_pcount).
            // The driver's public inputs are BYTES, so the delivered count
            // maps to ceil(bytes/mss) segments and the prior watermark is
            // translated through the packet total accumulated so far (a
            // plain ceil(prior_bytes/mss) would be wrong for short
            // segments, which are one packet each).
            const UInt64 total_before = total;
            const UInt64 total_pkts_before = total_pkts;
            const UInt64 delivered_pkts = (0 == delivered) ? 0
                : ((static_cast<UInt64>(delivered) + kMss - 1) / kMss);
            UInt64 prior_pkts;
            if (0 == prior_delivered) {
                prior_pkts = 0;
            } else if (prior_delivered >= total_before) {
                prior_pkts = total_pkts_before;
            } else {
                prior_pkts = (0 == total_before) ? 0
                    : (prior_delivered * total_pkts_before) / total_before;
            }
            now_us += interval_us;
            total += delivered;
            total_pkts += delivered_pkts;
            // Kernel rs->losses is a PACKET count (tcp_input_66.c:3936), and
            // KCC subtracts it from cwnd directly (tcp_kcc.c:3993). The
            // driver's public `lost` input is BYTES (it mirrors the port's
            // RateSample::lost), so translate once here and feed the same
            // packet count to both sides.
            const UInt64 lost_pkts = (0 == lost) ? 0
                : ((static_cast<UInt64>(lost) + kMss - 1) / kMss);
            ref.srtt_us = sk.srtt_us;
            kcc_core_on_ack_pkts(&ref, static_cast<s64>(now_us),
                                 static_cast<s64>(delivered_pkts), static_cast<s64>(rtt_us),
                                 static_cast<s64>(flight), static_cast<s64>(flight),
                                 static_cast<s64>(lost_pkts),
                                 static_cast<s64>(prior_pkts),
                                 static_cast<s64>(total_pkts),
                                 is_ack_delayed ? 1 : 0, is_app_limited ? 1 : 0,
                                 edt_us);
            RateSample rs;
            rs.delivered = delivered;
            rs.interval_us = interval_us;
            rs.rtt_us = rtt_us;
            rs.acked = delivered;
            rs.lost = lost;
            rs.lost_pkts = static_cast<UInt32>(lost_pkts);
            rs.is_app_limited = is_app_limited ? 1u : 0u;
            rs.prior_delivered = prior_delivered;
            rs.delivered_total = total;
            rs.is_ack_delayed = is_ack_delayed;
            rs.delivered_pkts = static_cast<UInt32>(delivered_pkts);
            rs.prior_delivered_pkts = prior_pkts;
            rs.delivered_total_pkts = total_pkts;
            rs.prior_in_flight_bytes = flight;
            rs.pacing_edt_us = edt_us;
            sk.inflight = flight;
            if (NULLPTR != ops) {
                ops->cong_control(&sk, &rs);
            }
        }

        void Round(UInt32 rtt_us, UInt32 delivered = kDelivered, UInt32 lost = 0,
                   bool delayed = false, bool app_limited = false) {
            const UInt32 interval = started ? last_rtt : ((0 < rtt_us) ? rtt_us : 1);
            const UInt64 prior = total;
            Ack(rtt_us, interval, delivered, lost, prior, delayed, app_limited);
            last_rtt = rtt_us;
            started = true;
        }

        /** @brief Kernel icsk_ca_state on BOTH sides (recovery differential). */
        void SetCaState(Byte state) {
            sk.ca_state = state;
            ref.ca_state = state;
        }
        /** @brief Kernel tp->prior_cwnd on BOTH sides. */
        void SetPriorCwnd(UInt32 cwnd) {
            sk.prior_cwnd = cwnd;
            ref.prior_cwnd = cwnd;
        }

        void InRound(UInt32 rtt_us, UInt32 interval_us = 1,
                     UInt32 delivered = kDelivered, UInt32 lost = 0,
                     bool delayed = false, bool app_limited = false) {
            Ack(rtt_us, interval_us, delivered, lost, 0, delayed, app_limited);
        }
    };

    void CheckFullSnapshot(Driver& d) {
        const KccSnapshot p = d.Snap();
        kcc_snapshot r;
        kcc_core_get_snapshot(&d.ref, &r);
        CHECK(p.x_est == r.x_est);
        CHECK(p.max_bw == r.max_bw);
        CHECK(p.full_bw == r.full_bw);
        CHECK(p.p_est == r.p_est);
        CHECK(p.qdelay_avg == r.qdelay_avg);
        CHECK(p.jitter_ewma == r.jitter_ewma);
        CHECK(p.sample_cnt == r.sample_cnt);
        CHECK(p.min_rtt_us == r.min_rtt_us);
        CHECK(p.rtt_cnt == r.rtt_cnt);
        CHECK(p.confirm_cnt == r.confirm_cnt);
        CHECK(p.confirm_slow_cnt == r.confirm_slow_cnt);
        CHECK(p.locked == r.locked);
        CHECK(p.locked_high_cnt == r.locked_high_cnt);
        CHECK(p.min_rtt_fast_fall_cnt == r.min_rtt_fast_fall_cnt);
        CHECK(p.x_est_fall_cnt == r.x_est_fall_cnt);
        CHECK(p.srtt_guard_cnt == r.srtt_guard_cnt);
        CHECK(p.srtt_suppress_cnt == r.srtt_suppress_cnt);
        CHECK(p.round_rtt_min == r.round_rtt_min);
        CHECK(p.prev_round_rtt_min == r.prev_round_rtt_min);
        CHECK(p.mode == r.mode);
        CHECK(p.pacing_gain == r.pacing_gain);
        CHECK(p.cwnd_gain == r.cwnd_gain);
        CHECK(p.cycle_idx == r.cycle_idx);
        CHECK(p.full_bw_reached == r.full_bw_reached);
        CHECK(p.full_bw_cnt == r.full_bw_cnt);
        CHECK(p.has_seen_rtt == r.has_seen_rtt);
        CHECK(p.idle_restart == r.idle_restart);
        CHECK(p.next_rtt_delivered == r.next_rtt_delivered);
        CHECK(p.total_delivered == r.total_delivered);
        CHECK(p.cycle_mstamp_us == r.cycle_mstamp_us);
        CHECK(p.last_ack_us == r.last_ack_us);
        CHECK(p.drain_enter_stamp_us == r.drain_enter_stamp_us);
        CHECK(p.rand_state == r.rand_state);
        // Recovery interaction (kcc_set_cwnd_to_recover_or_restore).
        CHECK(p.ca_state == r.ca_state);
        CHECK(p.prev_ca_state == r.prev_ca_state);
        CHECK(p.prior_cwnd == r.prior_cwnd);
        CHECK(p.packet_conservation == r.packet_conservation);
    }

    void CheckRefCommon(Driver& d) {
        const KccSnapshot s = d.Snap();
        CHECK(s.x_est == kcc_core_x_est(&d.ref));
        CHECK(s.p_est == kcc_core_p_est(&d.ref));
        CHECK(s.qdelay_avg == kcc_core_qdelay(&d.ref));
        CHECK(s.min_rtt_us == kcc_core_min_rtt(&d.ref));
        CHECK(s.mode == kcc_core_mode(&d.ref));
        CHECK(static_cast<s64>(s.max_bw) == d.ref.max_bw);
    }

    void TestKccG3PathIncreasePerRound() {
        Driver d;
        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(20000);
        }
        CHECK(20000 == d.Snap().min_rtt_us);

        UInt32 detected = 0;
        KccSnapshot s = d.Snap();
        for (UInt32 r = 1; r <= 8; ++r) {
            d.Round(200000);
            s = d.Snap();
            CHECK(s.min_rtt_us == d.ref.min_rtt_us);
            if (190000 <= s.min_rtt_us) {
                detected = r;
                break;
            }
        }
        CHECK(0 < detected);
        CHECK(detected <= 7);
        CHECK(200000 == s.min_rtt_us);
        CHECK(200000 == d.ref.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccG3PerRoundEvidence() {
        Driver d;
        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(20000);
        }

        // A single 25ms round with 20 ACKs. Counting per ACK used to reach
        // six consecutive exceedances inside this one round.
        d.Round(25000);
        for (UInt32 i = 1; i < 20; ++i) {
            d.InRound(25000);
        }
        KccSnapshot s = d.Snap();
        CHECK(0 == s.confirm_cnt);
        CHECK(s.confirm_cnt <= 1);
        CHECK(25000 == s.round_rtt_min);
        CHECK(20000 == s.min_rtt_us);

        // The next round boundary sees one elevated round => at most one count.
        d.Round(20000);
        s = d.Snap();
        CHECK(s.confirm_cnt <= 1);
        CHECK(s.confirm_slow_cnt <= 1);
        CHECK(20000 == s.min_rtt_us);

        // A clean baseline round breaks the chain.
        d.Round(20000);
        s = d.Snap();
        CHECK(0 == s.confirm_cnt);
        CHECK(0 == s.confirm_slow_cnt);
        CHECK(20000 == s.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccLockRelease() {
        Driver d;
        d.Round(4000);
        KccSnapshot s = d.Snap();
        CHECK(1 == s.locked);
        CHECK(4000 == s.min_rtt_us);

        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(40000);
        }
        s = d.Snap();
        CHECK(0 == s.locked);
        CHECK(40000 == s.min_rtt_us);
        CHECK(40000 == d.ref.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccLongPathOutlierDoesNotLock() {
        Driver d;
        for (UInt32 i = 0; i < 5; ++i) {
            d.Round(20000);
        }
        d.Round(4000);
        KccSnapshot s = d.Snap();
        CHECK(0 == s.locked);
        CHECK(20000 == s.min_rtt_us);

        // G3 must still work after the outlier.
        for (UInt32 i = 0; i < 7; ++i) {
            d.Round(200000);
        }
        s = d.Snap();
        CHECK(200000 == s.min_rtt_us);
        CHECK(200000 == d.ref.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccStickyAndFastFall() {
        // Sticky: 5 consecutive rounds below 0.75 * min_rtt (kcc_model).
        {
            Driver d;
            for (UInt32 i = 0; i < 5; ++i) {
                d.Round(20000);
            }
            for (UInt32 i = 0; i < 4; ++i) {
                d.Round(10000);
                CHECK(20000 == d.Snap().min_rtt_us);
            }
            d.Round(10000);
            KccSnapshot s = d.Snap();
            CHECK(10000 == s.min_rtt_us);
            CHECK(10000 == d.ref.min_rtt_us);
            CheckRefCommon(d);
        }

        // Fast fall: a drop below min_rtt/4 needs two consecutive rounds.
        {
            Driver d;
            for (UInt32 i = 0; i < 5; ++i) {
                d.Round(20000);
            }
            d.Round(4000);
            CHECK(20000 == d.Snap().min_rtt_us);
            CHECK(1 == d.Snap().min_rtt_fast_fall_cnt);
            d.Round(4000);
            KccSnapshot s = d.Snap();
            CHECK(4000 == s.min_rtt_us);
            CHECK(4000 == d.ref.min_rtt_us);
            CheckRefCommon(d);
        }
    }

    void TestKccSrttGuard() {
        // Stable srtt below min_rtt must engage after five rounds.
        {
            Driver d(20000, 10000);
            for (UInt32 i = 0; i < 10; ++i) {
                d.Round(20000);
            }
            KccSnapshot s = d.Snap();
            CHECK(10000 == s.min_rtt_us);
            CHECK(10000 == d.ref.min_rtt_us);
            CheckRefCommon(d);
        }

        // A G3-confirmed path increase must survive a lagging srtt.
        {
            Driver d(20000, 20000);
            for (UInt32 i = 0; i < 10; ++i) {
                d.Round(20000);
            }
            UInt32 detected = 0;
            for (UInt32 r = 1; r <= 8; ++r) {
                d.Round(200000);
                if (190000 <= d.Snap().min_rtt_us) {
                    detected = r;
                    break;
                }
            }
            CHECK(0 < detected && detected <= 7);
            for (UInt32 i = 0; i < 10; ++i) {
                d.Round(200000);
                CHECK(190000 <= d.Snap().min_rtt_us);
            }
            CHECK(200000 == d.ref.min_rtt_us);
            CheckRefCommon(d);
        }
    }

    void TestKccG2PerRound() {
        Driver d;
        d.Round(20000);
        CHECK((UInt64(20000) << 10) == d.Snap().x_est);

        // Two ACKs inside the same round must not grow x_est.
        d.InRound(21000);
        CHECK((UInt64(20000) << 10) == d.Snap().x_est);
        d.InRound(22000);
        KccSnapshot s = d.Snap();
        CHECK((UInt64(20000) << 10) == s.x_est);
        CHECK(1125 == s.qdelay_avg);                     // kcc_model same-round golden

        // Next round applies one 12.2% G2 step, capped at the observation.
        d.Round(30000);
        s = d.Snap();
        CHECK((UInt64(22440) << 10) == s.x_est);         // kcc_model golden
        CHECK(1500 <= s.qdelay_avg);
        CHECK(2234 == s.qdelay_avg);                     // kcc_model golden
        CheckRefCommon(d);
    }

    void TestKccQdelayBaseline() {
        Driver d;
        d.Round(20000);
        // 100 ACKs in one round: a gradual 10ms queue build. The qdelay
        // baseline is the confirmed min_rtt, not x_est (which stays at the
        // observed 20ms because G2 runs once per round).
        for (UInt32 i = 0; i < 100; ++i) {
            d.InRound(20000 + i * 100);
        }
        KccSnapshot s = d.Snap();
        CHECK(9200 == s.qdelay_avg);                     // kcc_model golden
        CHECK((UInt64(20000) << 10) == s.x_est);
        CHECK(20000 == s.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccStalenessDownwardOnly() {
        Driver d;
        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(20000);
        }
        for (UInt32 i = 0; i < 7; ++i) {
            d.Round(40000);
        }
        CHECK(40000 == d.Snap().min_rtt_us);
        for (UInt32 i = 0; i < 127; ++i) {
            d.Round(40000);
        }
        // This sample is the 128th round since the last min_rtt update and
        // therefore the first staleness evaluation. Downward-only: x_est
        // must not be raised to 95% of min_rtt.
        d.Round(10000);
        KccSnapshot s = d.Snap();
        CHECK((UInt64(10000) << 10) == s.x_est);
        CHECK(40000 == s.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccFullBwThresholdMatchesKernel() {
        Driver d;
        UInt32 delivered = 14600;
        bool reached = false;
        for (UInt32 i = 0; i < 8; ++i) {
            d.Round(10000, delivered);
            KccSnapshot s = d.Snap();
            // Kernel full-bw detection runs on the round_start sample, so the
            // plateau count starts one round earlier than the old time-round
            // port. The detection sample itself enters DRAIN (mode 2).
            if (i == 3) {
                CHECK(1 == s.full_bw_reached);
                CHECK(2 == s.mode);                      // DRAIN on entry
                CHECK(1 == d.ref.full_bw_reached);
                CHECK(2 == d.ref.mode);
                reached = true;
            }
            // 3%/round keeps the three-round growth below 1.25x, which is
            // what the kernel's plateau detector measures (a 10%/round
            // staircase would refresh full_bw on the fourth round instead).
            delivered += delivered * 3 / 100;
        }
        CHECK(reached);
        CHECK(1 == d.Snap().full_bw_reached);
    }

    void TestKccProbeCycleAdvances() {
        Driver d;
        const UInt32 delivered = 29200;
        UInt64 rates[12] = {0};
        UInt32 cycles[12] = {0};
        for (UInt32 i = 0; i < 12; ++i) {
            d.Round(20000, delivered);
            rates[i] = d.sk.pacing_rate;
            cycles[i] = d.Snap().cycle_idx;
            CHECK(20000 == d.Snap().min_rtt_us);
        }
        // PIN (delivered-round + kernel order):
        //  0-2 STARTUP; 3-4 DRAIN (detection sample enters DRAIN; exit at
        //  +2*min_rtt); 5-7 probe-up 1.25x (2*min_rtt timeout bounds it);
        //  8-9 drain phase 0.75x; 10-11 cruise 1.0x.
        for (UInt32 i = 0; i < 3; ++i) {
            CHECK(kStartupRate == rates[i]);
        }
        CHECK(kDrainModeRate == rates[3]);
        CHECK(kDrainModeRate == rates[4]);
        CHECK(kProbeRate == rates[5]);
        CHECK(kProbeRate == rates[6]);
        CHECK(kProbeRate == rates[7]);
        CHECK(kDrainRate == rates[8]);
        CHECK(kDrainRate == rates[9]);
        CHECK(kCruiseRate == rates[10]);
        CHECK(kCruiseRate == rates[11]);
        CHECK(0 == cycles[5]);
        CHECK(0 == cycles[6]);
        CHECK(0 == cycles[7]);
        CHECK(1 == cycles[8]);
        CHECK(1 == cycles[9]);
        CHECK(2 == cycles[10]);
        CHECK(2 == cycles[11]);
        CheckRefCommon(d);
    }

    void TestKccPacingExtremeClamp() {
        Driver d;
        d.Ack(1000, 1, 0xFFFFFFFFu);
        const KccSnapshot s = d.Snap();
        // Kernel clamps the packet-domain estimate to U32_MAX.
        CHECK(0xFFFFFFFFull == s.max_bw);
        CHECK(kPacingExtreme == d.sk.pacing_rate);
        CHECK(static_cast<s64>(kPacingExtreme) == kcc_core_pacing_rate(&d.ref));
        CheckRefCommon(d);
    }

    /**
     * @brief B8-D7(c): the pacing rate must respect sk_max_pacing_rate.
     *
     * Kernel kcc_bw_to_pacing_rate (tcp_kcc.c:3563-3567) returns
     *   min_t(u64, kcc_rate_bytes_per_sec(sk, bw, gain), sk->sk_max_pacing_rate)
     * and kcc_set_pacing_rate (tcp_kcc.c:3599-3637) assigns only that value,
     * so a user SO_MAX_PACING_RATE caps the STARTUP ramp and the monotonic
     * gate compares capped values. The port had no clamp at all, so KCC paced
     * above the user's ceiling.
     *
     * Red baseline (no clamp): pacing_rate == 1068150599751 with a 1 MB/s cap.
     */
    void TestKccMaxPacingRateClamp() {
        {
            // STARTUP (full_bw_reached == 0): the monotonic branch.
            Driver d;
            const UInt64 cap = 1000000;  // 1 MB/s
            d.sk.max_pacing_rate = cap;
            d.ref.max_pacing_rate = cap;
            d.Ack(1000, 1, 0xFFFFFFFFu);
            std::fprintf(stderr, "[D7c] startup pacing=%llu cap=%llu\n",
                         static_cast<unsigned long long>(d.sk.pacing_rate),
                         static_cast<unsigned long long>(cap));
            CHECK(cap == d.sk.pacing_rate);
            CHECK(static_cast<s64>(cap) == kcc_core_pacing_rate(&d.ref));
            CheckRefCommon(d);
        }
        {
            // Post-STARTUP (full_bw_reached == 1): reach it naturally with the
            // 3%/round staircase the plateau detector needs.
            Driver d;
            const UInt64 cap = 1000000;
            d.sk.max_pacing_rate = cap;
            d.ref.max_pacing_rate = cap;
            UInt32 delivered = 14600;
            for (UInt32 i = 0; i < 8; ++i) {
                d.Round(10000, delivered);
                delivered += delivered * 3 / 100;
            }
            CHECK(1 == d.Snap().full_bw_reached);
            CHECK(1 == d.ref.full_bw_reached);
            std::fprintf(stderr, "[D7c] post-startup pacing=%llu cap=%llu\n",
                         static_cast<unsigned long long>(d.sk.pacing_rate),
                         static_cast<unsigned long long>(cap));
            CHECK(d.sk.pacing_rate <= cap);
            CHECK(static_cast<s64>(d.sk.pacing_rate) == kcc_core_pacing_rate(&d.ref));
            CheckRefCommon(d);
        }
        {
            // No cap (kernel default ~0): the rate is unchanged.
            Driver d;
            d.Ack(1000, 1, 0xFFFFFFFFu);
            CHECK(kPacingExtreme == d.sk.pacing_rate);
            CHECK(static_cast<s64>(kPacingExtreme) == kcc_core_pacing_rate(&d.ref));
            CheckRefCommon(d);
        }
    }

    void TestKccBdpSaturation() {
        // product = max_bw * min_rtt overflows u64 on a long-stall RTT
        // (4s) with the clamped bandwidth. The saturated BDP must stay
        // positive and below the segment clamp, and pacing must stay valid.
        // The cwnd model is additive in STARTUP now (kernel kcc_set_cwnd:
        // cwnd += acked), so the old "one step to the saturated BDP
        // (>700M segments)" pin no longer applies - that was the
        // max(prev,BDP) behaviour being removed. Pin the exact additive
        // growth instead (explicit expectation change, not a regression).
        Driver d;
        d.Ack(4000000u, 1, 0xFFFFFFFFu);
        const KccSnapshot s = d.Snap();
        CHECK(0 != s.max_bw);
        const UInt64 expected = 10ull + (0xFFFFFFFFull + kMss - 1) / kMss;
        CHECK(expected == static_cast<UInt64>(d.sk.snd_cwnd));
        CHECK(d.sk.snd_cwnd <= 0x7FFFFFFFu);
        CHECK(0 < d.sk.pacing_rate);
        CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
        CheckRefCommon(d);
    }

    void TestKccPacingUnitGrid() {
        // Intervals are powers of two <= BW_SCALE, so the segment-domain
        // floor and the byte-domain floor are identical and the check can be
        // exact (the audit's <=1 B/s bound).
        const UInt32 segs[] = {1, 2, 10, 100};
        const UInt32 intervals[] = {1, 2, 4, 8, 16, 64, 256, 1024};
        const UInt32 kMinRtt = 1000000000u;   // seeds min_rtt; boot rate is 0
        for (UInt32 si = 0; si < 4; ++si) {
            for (UInt32 ii = 0; ii < 8; ++ii) {
                Driver d(kMinRtt);
                const UInt32 delivered = segs[si] * kMss;
                d.Ack(kMinRtt, intervals[ii], delivered);
                // Independent segment-domain kernel formula:
                // bw = segs << BW_SCALE / interval; rate = bw*mss*gain;
                // 1% converted by the BW_SCALE shift; USEC_PER_SEC fold.
                const UInt64 bw_seg = (static_cast<UInt64>(delivered / kMss) << 24) / intervals[ii];
                const UInt64 raw = (bw_seg * kMss * 739) >> 8;
                const UInt64 expected = (raw * 990000ull) >> 24;
                const UInt64 actual = d.sk.pacing_rate;
                const UInt64 diff = (actual > expected) ? (actual - expected)
                                                        : (expected - actual);
                CHECK(diff <= 1);
                if (diff > 1) {
                    std::fprintf(stderr, "grid seg=%u interval=%u actual=%llu expected=%llu\n",
                                 segs[si], intervals[ii],
                                 static_cast<unsigned long long>(actual),
                                 static_cast<unsigned long long>(expected));
                }
            }
        }
    }

    void TestKccBdpConfirmedBaseline() {
        Driver d;
        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(20000);
        }
        const UInt32 baseline_cwnd = d.sk.snd_cwnd;
        CHECK(0 < baseline_cwnd);

        d.Round(5000);
        KccSnapshot s = d.Snap();
        CHECK(20000 == s.min_rtt_us);
        CHECK(static_cast<UInt64>(d.sk.snd_cwnd) * 10 >=
              static_cast<UInt64>(baseline_cwnd) * 6);

        for (UInt32 i = 0; i < 3; ++i) {
            d.Round(20000);
        }
        s = d.Snap();
        CHECK(20000 == s.min_rtt_us);
        CHECK(static_cast<UInt64>(d.sk.snd_cwnd) * 10 >=
              static_cast<UInt64>(baseline_cwnd) * 6);
        CHECK(20000 == d.ref.min_rtt_us);
        CheckRefCommon(d);
    }

    void TestKccColdStart() {
        {
            Driver d;
            CHECK(1000 == d.Snap().min_rtt_us);
            d.Round(20000);
            KccSnapshot s = d.Snap();
            CHECK(20000 == s.min_rtt_us);
            CHECK((UInt64(20000) << 10) == s.x_est);
            CHECK(0 < d.sk.pacing_rate);
            CHECK(20000 == d.ref.min_rtt_us);
            CheckRefCommon(d);
        }
        {
            // A real init seed must be preserved (not replaced as placeholder).
            Driver d(8000);
            CHECK(8000 == d.Snap().min_rtt_us);
            d.Round(20000);
            CHECK(8000 == d.Snap().min_rtt_us);
            CHECK(8000 == d.ref.min_rtt_us);
        }
    }

    void TestKccDifferential() {
        Driver d;
        // Deterministic RTT sequence: starts at 30ms, dips to 20ms (new min),
        // then a slow upward drift with noise.
        UInt32 seed = 0xABCD1234;
        const auto next = [&seed]() -> UInt32 {
            seed = seed * 1664525u + 1013904223u;
            return seed;
        };

        const UInt32 kSteps = 3000;
        UInt32 cycle_moves = 0;
        UInt32 last_cycle = d.Snap().cycle_idx;
        for (UInt32 i = 0; i < kSteps; ++i) {
            UInt32 rtt_us;
            if (i < 200) {
                rtt_us = 30000 - i * 5;              // 30ms -> 29ms
            } else if (i < 400) {
                rtt_us = 20000 + (next() % 500);     // new min ~20ms
            } else {
                rtt_us = 20000 + (i % 1000) * 3 + (next() % 2000);
            }
            const UInt32 acked = 1 + (next() % 4);
            const UInt32 delivered = acked * kMss;
            const UInt32 lost = (0 == (i % 700)) ? delivered : 0;
            // B8-D2: a DELIVERED round boundary must move with the ACK
            // stream. Ack()'s default prior_delivered = 0 opens only the
            // very first round, so the old 3000-step loop never left
            // STARTUP. Round() passes the pre-ACK delivered total.
            d.Round(rtt_us, delivered, lost);
            const KccSnapshot s = d.Snap();
            if (s.cycle_idx != last_cycle) {
                ++cycle_moves;
                last_cycle = s.cycle_idx;
            }

            CheckFullSnapshot(d);
            CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
            CHECK(kcc_core_pacing_rate(&d.ref) == static_cast<s64>(d.sk.pacing_rate));
            if (0 < g_failures) {
                std::fprintf(stderr, "differential mismatch at step %u\n", i);
                break;
            }
        }
        // Coverage guard (B8-D2): the stream must exercise delivered rounds,
        // full-bw detection (STARTUP -> DRAIN) and the PROBE_BW cycle.
        CHECK(4 <= d.Snap().rtt_cnt);
        CHECK(0 != d.Snap().full_bw_reached);
        CHECK(0 < cycle_moves);
    }

    void TestKccRegistry() {
        xtcp::cc::RegisterKcc();
        const XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("kcc");
        CHECK(NULLPTR != ops);
        CHECK(0 == std::strcmp("kcc", ops->name));

        XtcpConnCc sk;
        ops->init(&sk);
        sk.mss = kMss;
        CHECK(NULLPTR != sk.ca_priv);

        // Initial state: STARTUP, cwnd = 10.
        CHECK(10 == sk.snd_cwnd);
        ops->release(&sk);
        CHECK(NULLPTR == sk.ca_priv);
    }

    void TestKccRoundBoundaryTracksFlight() {
        // Delivered-round semantics: a burst of ACK-clock samples whose
        // segments were all sent before the same delivered watermark opens
        // exactly ONE round regardless of how many ACKs arrive.
        Driver d;
        constexpr UInt32 kFirstDelivered = 10 * kMss;
        constexpr UInt32 kInterval = 100;

        for (UInt32 i = 0; i < 10; ++i) {
            const UInt32 delivered = (0 == i) ? kFirstDelivered : kMss;
            d.InRound(1000, kInterval, delivered);
            CHECK(1 == d.ref.rtt_cnt);
            CHECK(1 == d.Snap().rtt_cnt);
            CHECK(0 == d.ref.full_bw_cnt);
            CHECK(static_cast<UInt32>(kcc_core_cwnd_segs(&d.ref)) == d.sk.snd_cwnd);
        }
        // The boundary was captured at the first sample (10*mss); the ACK
        // clock alone does not move it.
        // Packet domain: the watermark is a segment count (10 MSS = 10).\n        CHECK(static_cast<UInt64>(kFirstDelivered / kMss) == d.Snap().next_rtt_delivered);

        // A segment sent after the round watermark advances it exactly once.
        d.Round(1000, kMss);
        CHECK(2 == d.ref.rtt_cnt);
        CHECK(2 == d.Snap().rtt_cnt);
        const KccSnapshot s = d.Snap();
        CHECK(d.total_pkts == s.next_rtt_delivered);  // boundary tracks delivered_total_pkts
        CHECK(static_cast<UInt32>(kcc_core_cwnd_segs(&d.ref)) == d.sk.snd_cwnd);
    }

    void TestKccRoundBoundaryTracksCurrentRtt() {
        // RTT changes must NOT drive round boundaries: only the delivered
        // watermark does. Same burst + changing RTT stays in one round.
        Driver d;
        const UInt32 kFastDelivered = 10 * kMss;
        const auto sample = [&](UInt32 delivered, UInt32 interval_us, UInt32 rtt_us) {
            d.InRound(rtt_us, interval_us, delivered);
            CHECK(static_cast<UInt32>(kcc_core_cwnd_segs(&d.ref)) == d.sk.snd_cwnd);
        };

        sample(kFastDelivered, 100, 1000);
        CHECK(1 == d.ref.rtt_cnt);
        const s64 max_bw = (static_cast<s64>(kFastDelivered / kMss) << 24) / 100;
        CHECK(max_bw == d.ref.max_bw);
        for (UInt32 i = 0; i < 20; ++i) {
            sample(kMss, 400, 4000);
            CHECK(1 == d.ref.rtt_cnt);   // still the same delivered round
        }
        const KccSnapshot s = d.Snap();
        CHECK(static_cast<UInt64>(kFastDelivered / kMss) == s.next_rtt_delivered);
    }

    void TestKccFullBwTransition() {
        // PIN: full-bw detection must fire on 3 consecutive PLATEAU rounds
        // (growth < 1.25x/round) and drive STARTUP -> DRAIN -> PROBE_BW.
        // Delivered-round detection fires on sample 4; the detection sample
        // enters DRAIN, and the 2*min_rtt timeout bounds probe-up at samples
        // 5-7. Sample 8 advances to the 0.75x phase, sample 10 to cruise.
        Driver d;
        const UInt32 kDeliveredSample = 29200;
        UInt64 rates[12] = {0};
        for (UInt32 i = 0; i < 12; ++i) {
            d.Round(20000, kDeliveredSample);
            rates[i] = d.sk.pacing_rate;
        }
        for (UInt32 i = 0; i < 3; ++i) {
            CHECK(kStartupRate == rates[i]);
        }
        CHECK(kDrainModeRate == rates[3]);   // DRAIN on the detection sample
        CHECK(kDrainModeRate == rates[4]);
        CHECK(kProbeRate == rates[5]);
        CHECK(kProbeRate == rates[6]);
        CHECK(kProbeRate == rates[7]);       // probe-up timeout at 2*min_rtt
        CHECK(kDrainRate == rates[8]);
        CHECK(kDrainRate == rates[9]);
        CHECK(kCruiseRate == rates[10]);
        CHECK(kCruiseRate == rates[11]);
    }

    // ------------------------------------------------------------------
    // Residual-limits wave (delivered round / delayed ACK / cycle / DRAIN /
    // cwnd) plus FSM collection tests.
    // ------------------------------------------------------------------

    /* Feed rounds until STARTUP detects the pipe is full. The detection
     * sample itself enters DRAIN (kernel kcc_check_drain order). */
    KccSnapshot FeedFullBw(Driver& d, UInt32 rtt_us = 10000) {
        UInt32 delivered = 14600;
        KccSnapshot detection;
        for (UInt32 i = 0; i < 5; ++i) {
            d.Round(rtt_us, delivered);
            if (3 == i) {
                detection = d.Snap();
            }
            // Grow slower than 1.25x over three rounds: the kernel only
            // refreshes full_bw when a round is >= 1.25x, so a 10%/round
            // staircase never plateaus against the stale reference.
            delivered += delivered * 3 / 100;
        }
        CHECK(2 == d.Snap().mode);
        CHECK(2 == detection.mode);
        return detection;
    }

    /* Drive STARTUP -> DRAIN -> PROBE_BW and return the first PROBE sample. */
    KccSnapshot ForceProbe(Driver& d, UInt32 rtt_us = 10000) {
        FeedFullBw(d, rtt_us);
        d.flight = 0;
        d.Round(rtt_us, 14600);
        const KccSnapshot s = d.Snap();
        CHECK(1 == s.mode);
        return s;
    }

    void TestKccDeliveredRound() {
        {
            // Same-burst: 1 first sample + 5 ACKs for segments that were all
            // sent before the same delivered watermark -> exactly ONE round.
            Driver d;
            d.Ack(20000, 20000, 10 * kMss, 0, 0);
            for (UInt32 i = 0; i < 5; ++i) {
                d.Ack(20000, 1, kMss, 0, 0);
            }
            const KccSnapshot s = d.Snap();
            CHECK(1 == s.rtt_cnt);
            CHECK(10ull == s.next_rtt_delivered);   // 10 MSS = 10 packets
            CHECK(d.total_pkts == s.next_rtt_delivered + 5ull);
        }
        {
            // ACK-clocked: every segment was sent after the previous round's
            // watermark -> one round per sample.
            Driver d;
            for (UInt32 i = 0; i < 10; ++i) {
                const UInt64 prior = d.total;
                d.Ack(1000, 100, 100 * kMss, 0, prior);
                CHECK(i + 1 == d.Snap().rtt_cnt);
                CHECK(d.total_pkts == d.Snap().next_rtt_delivered);
            }
        }
    }

    void TestKccDelayedAckFiltered() {
        Driver d;
        for (UInt32 i = 0; i < 20; ++i) {
            d.Round(20000);
        }
        CHECK(20000 == d.Snap().min_rtt_us);
        for (UInt32 i = 0; i < 8; ++i) {
            d.Round(45000, kDelivered, 0, true);
            // A delayed sample must not become the round's minimum.
            CHECK(0xFFFFFFFFu == d.Snap().round_rtt_min);
        }
        const KccSnapshot s = d.Snap();
        CHECK(20000 == s.min_rtt_us);     // G3 chain was not polluted
        CHECK(20000 == d.ref.min_rtt_us);
        // A real sample still updates the round statistic.
        d.Round(20000);
        CHECK(20000 == d.Snap().round_rtt_min);
        CheckRefCommon(d);
    }

    void TestKccDelayedAckTruthTable() {
        using xtcp::cc::IsLikelyDelayedAck;
        // acked, popped, len, retrans, prior_sacked, ece, sack, sent, after, mss
        CHECK(IsLikelyDelayedAck(100, 1, 100, false, false, false, false, 500, 600, kMss));
        CHECK(!IsLikelyDelayedAck(kMss, 1, kMss, false, false, false, false, 0, kMss, kMss));
        CHECK(!IsLikelyDelayedAck(200, 2, 100, false, false, false, false, 400, 600, kMss));
        CHECK(!IsLikelyDelayedAck(100, 1, 100, true, false, false, false, 500, 600, kMss));
        CHECK(!IsLikelyDelayedAck(100, 1, 100, false, true, false, false, 500, 600, kMss));
        CHECK(!IsLikelyDelayedAck(100, 1, 100, false, false, true, false, 500, 600, kMss));
        CHECK(!IsLikelyDelayedAck(100, 1, 100, false, false, false, true, 500, 600, kMss));
        CHECK(!IsLikelyDelayedAck(100, 1, 100, false, false, false, false, 450, 600, kMss));
        CHECK(!IsLikelyDelayedAck(100, 1, 150, false, false, false, false, 500, 600, kMss));
        CHECK(!IsLikelyDelayedAck(0, 1, 100, false, false, false, false, 500, 600, kMss));
    }

    void TestKccDrainExit() {
        {
            // Not drained: a huge pipe only leaves via the 4*min_rtt timeout.
            Driver d;
            const KccSnapshot entry = FeedFullBw(d);
            // Kernel kcc_check_drain sets snd_ssthresh = kcc_inflight(...),
            // which is the BDP WITH the quantization budget
            // (kcc_quantization_budget: += 3 * tso_segs_goal, then even-align),
            // not the bare BDP (audit B6-D2).
            const UInt64 bdp = kcc_bdp_packets(entry.max_bw, entry.min_rtt_us, 256);
            const UInt32 tso_goal = xtcp::cc::KccTestTsoSegsGoal(&d.sk);
            const UInt64 expected_ssthresh = (bdp + 3ull * tso_goal + 1ull) & ~UInt64(1);
            // The budget depends on the pacing rate AT the DRAIN entry, which
            // the post-hoc probe cannot reconstruct exactly (pacing_rate has
            // already advanced). Assert the invariant instead: ssthresh is the
            // even-aligned BDP plus 3*tso_goal for SOME tso_goal in 1..127,
            // i.e. strictly above the bare BDP and within the documented cap.

            CHECK(bdp < d.sk.snd_ssthresh);
            CHECK(0 == (d.sk.snd_ssthresh & 1u));            // even-aligned
            CHECK(d.sk.snd_ssthresh <= bdp + 3ull * 127u + 1u);
            CHECK(expected_ssthresh <= d.sk.snd_ssthresh + 6u);
            CHECK(entry.drain_enter_stamp_us == entry.last_ack_us);
            d.flight = 300000;  // ~10x BDP, never drained
            UInt32 delivered = 14600;
            // Detection happened at round 4; FeedFullBw's fifth sample put
            // elapsed at 10ms. These three samples reach 20/30/40ms, which
            // never exceeds the 4*min_rtt (40ms) timeout.
            for (UInt32 i = 0; i < 3; ++i) {
                d.Round(10000, delivered);
                CHECK(2 == d.Snap().mode);
            }
            d.Round(10000, delivered);       // elapsed 50ms > 4*min_rtt
            CHECK(1 == d.Snap().mode);
        }
        {
            // Drained: FeedFullBw's fifth sample already moved elapsed to
            // 10ms (== min_rtt, strict '>' false); the next sample reaches
            // 20ms with the pipe drained and exits.
            Driver d;
            FeedFullBw(d);
            d.flight = 0;
            d.Round(10000, 14600);
            CHECK(1 == d.Snap().mode);
        }
    }

    /**
     * @brief Kernel kcc_packets_in_net_at_edt EDT credit (tcp_kcc.c:5016-5037).
     *
     *   interval_delivered = (bw * interval_us) >> BW_SCALE
     *   inflight_at_edt    = ceil(inflight/mss) + (gain > 256 ? 1 : 0)
     *   credit >= inflight_at_edt -> 0
     *   else (inflight_at_edt - credit) * mss
     *
     * Row 1 pins backward compatibility: edt_us == 0 must reproduce the old
     * value exactly (no credit, only the gain headroom).
     */
    void TestKccDrainEdtCredit() {
        using xtcp::cc::KccTestPacketsInNetAtEdt;
        const UInt32 mss = kMss;               // 1460
        const UInt64 bw = 1ull << 24;          // 1 segment per microsecond

        // Row 1: edt_us == 0 -> identical to the old (credit-free) formula.
        CHECK(2 * mss == KccTestPacketsInNetAtEdt(2 * mss, 256, mss, bw, 0, 1));
        CHECK(3 * mss == KccTestPacketsInNetAtEdt(2 * mss, 288, mss, bw, 0, 1));  // +1 seg
        // Sub-MSS remainder still counts as one whole packet (kernel ceil).
        CHECK(mss == KccTestPacketsInNetAtEdt(1, 256, mss, bw, 0, 1));

        // Row 2: credit >= inflight -> 0. 3 us at 1 seg/us credits 3 packets.
        CHECK(0 == KccTestPacketsInNetAtEdt(2 * mss, 256, mss, bw, 3, 1));
        CHECK(0 == KccTestPacketsInNetAtEdt(2 * mss, 288, mss, bw, 4, 1));

        // Row 3: partial credit -> exactly (pkts - credit) * mss.
        // 2 in flight, 1 us credit -> 1 packet left.
        CHECK(mss == KccTestPacketsInNetAtEdt(2 * mss, 256, mss, bw, 1, 1));
        // 5 in flight + gain headroom, 2 us credit -> 4 packets.
        CHECK(4 * mss == KccTestPacketsInNetAtEdt(5 * mss, 288, mss, bw, 2, 1));
        // Half-rate bw: 1 us credits 0.5 packet -> floor(credit) == 0.
        CHECK(5 * mss == KccTestPacketsInNetAtEdt(5 * mss, 256, mss, bw / 2, 1, 1));
        // 2 us at half rate credits 1 packet -> 4 left.
        CHECK(4 * mss == KccTestPacketsInNetAtEdt(5 * mss, 256, mss, bw / 2, 2, 1));

        // mss == 0 falls back to 1460 (never divides by zero).
        CHECK(2 * 1460 == KccTestPacketsInNetAtEdt(2 * 1460, 256, 0, bw, 0, 1));
    }

    UInt32 ProbePhaseForSeed(UInt32 seed) {
        xtcp::cc::KccTestSetRandomSeed(seed);
        Driver d(0, 0, seed);
        const KccSnapshot s = ForceProbe(d);
        return s.cycle_idx;
    }

    void TestKccCycleRandomized() {
        // Fixed seed 2 reproduces the historical phase-0 sequence.
        CHECK(0 == ProbePhaseForSeed(2));
        CHECK(0 == ProbePhaseForSeed(2));
        // The kernel mapping never starts at phase 1 (drain) and is
        // reproducible per seed.
        for (UInt32 seed = 0; seed < 32; ++seed) {
            const UInt32 phase = ProbePhaseForSeed(seed);
            CHECK(1 != phase);
            CHECK(phase < 8);
            CHECK(phase == ProbePhaseForSeed(seed));
        }
        // Production-style counter seeding decorrelates connections.
        xtcp::cc::KccTestSetRandomCounter(1);
        UInt32 phases[8] = {0};
        for (UInt32 i = 0; i < 8; ++i) {
            Driver d(0, 0, 1);
            phases[i] = ForceProbe(d).cycle_idx;
        }
        bool differ = false;
        for (UInt32 i = 1; i < 8; ++i) {
            if (phases[i] != phases[0]) {
                differ = true;
            }
        }
        CHECK(differ);
        xtcp::cc::KccTestSetRandomSeed(2);
    }

    UInt64 ExpectedPacing(UInt64 bw) {
        // Haircut(MulShr8(bw, 1.0x)) with BBR_UNIT=256.
        const UInt64 v = bw;
        const UInt64 hi = v >> 8;
        UInt64 scaled = (0 != hi && hi > (~UInt64(0)) / 256) ? ~UInt64(0)
                                                            : hi * 256 + (((v & 0xFFu) * 256) >> 8);
        const UInt64 q = scaled >> 24;
        const UInt64 r = scaled & ((UInt64(1) << 24) - 1);
        return q * 990000ull + ((r * 990000ull) >> 24);
    }

    void TestKccIdleRestart() {
        xtcp::cc::KccTestSetRandomSeed(2);
        Driver d(0, 0, 2);
        const KccSnapshot probe = ForceProbe(d);
        CHECK(0 == probe.cycle_idx);
        const UInt64 rate_before = d.sk.pacing_rate;
        d.sk.app_limited = 1;
        d.ops->cwnd_event(&d.sk, xtcp::cc::kCaEventTxStart);
        KccSnapshot s = d.Snap();
        CHECK(1 == s.idle_restart);
        CHECK(s.cycle_mstamp_us == s.last_ack_us);
        CHECK(ExpectedPacing(s.max_bw * kMss) == d.sk.pacing_rate);
        (void)rate_before;

        // No app-limited marker: the event has no effect.
        d.Round(20000, kDelivered);       // delivered>0 clears idle_restart
        CHECK(0 == d.Snap().idle_restart);
        const UInt64 stamp = d.Snap().cycle_mstamp_us;
        d.sk.app_limited = 0;
        d.ops->cwnd_event(&d.sk, xtcp::cc::kCaEventTxStart);
        s = d.Snap();
        CHECK(0 == s.idle_restart);
        CHECK(stamp == s.cycle_mstamp_us);
    }

    void TestKccCwndStartup() {
        // Same-burst ACK clock (no further round boundaries): STARTUP grows
        // additively while delivered_total < 10*mss or cwnd < target.
        Driver d(20000);
        CHECK(10 == d.sk.snd_cwnd);
        for (UInt32 i = 0; i < 10; ++i) {
            d.Ack(20000, 20000, kMss, 0, 0);
        }
        CHECK(19 == d.sk.snd_cwnd);
        CHECK(static_cast<s64>(d.sk.snd_cwnd) == kcc_core_cwnd_segs(&d.ref));
    }

    void TestKccCwndLossAndCap() {
        Driver d;
        // Kernel kcc_ssthresh is a PASS-THROUGH: it saves prior_cwnd and
        // returns the current snd_ssthresh without touching the window (the
        // cut itself is the FSM's cwnd = inflight + 1).
        const UInt32 prior = d.sk.snd_cwnd;
        const UInt32 hook_ssthresh = d.ops->ssthresh(&d.sk);
        CHECK(0x7FFFFFFFu == hook_ssthresh);
        CHECK(prior == d.sk.snd_cwnd);
        CHECK(prior == d.sk.prior_cwnd);
        // The FSM-side cut leaves the window at the reduced value; the growth
        // assertions below are unchanged.
        d.sk.snd_cwnd = 4;
        d.ref.cwnd_segs = 4;
        d.Ack(20000, 20000, kMss, 0, 0);
        CHECK(5 == d.sk.snd_cwnd);
        d.Ack(20000, 20000, kMss, 0, 0);
        CHECK(6 == d.sk.snd_cwnd);
        CHECK(static_cast<s64>(d.sk.snd_cwnd) == kcc_core_cwnd_segs(&d.ref));

        // Loss is deducted from the base before growth (kernel order).
        Driver e;
        e.Ack(20000, 20000, kMss, 2 * kMss, 0);
        CHECK(9 == e.sk.snd_cwnd);   // (10*MSS - 2920 + 1460) / MSS
        CHECK(static_cast<s64>(e.sk.snd_cwnd) == kcc_core_cwnd_segs(&e.ref));
    }

    /**
     * @brief Kernel kcc_ssthresh pass-through + kcc_undo_cwnd contract.
     */
    void TestKccSsthreshPassthroughAndUndo() {
        Driver d;
        d.sk.snd_cwnd = 20;
        d.sk.snd_ssthresh = 18;
        const UInt32 ret = d.ops->ssthresh(&d.sk);
        CHECK(18 == ret);            // returns the CURRENT ssthresh
        CHECK(20 == d.sk.snd_cwnd);  // never writes the window
        CHECK(20 == d.sk.prior_cwnd);
        CHECK(18 == d.sk.snd_ssthresh);  // unchanged by the hook

        // kcc_undo_cwnd returns the current window and clears full_bw.
        const KccSnapshot before = d.Snap();
        const UInt32 undo = d.ops->undo_cwnd(&d.sk);
        CHECK(20 == undo);
        CHECK(20 == d.sk.snd_cwnd);
        const KccSnapshot after = d.Snap();
        CHECK(0ull == after.full_bw);
        CHECK(0u == after.full_bw_cnt);
        (void)before;

        // set_state(CA_Loss) also clears full_bw.
        d.ops->set_state(&d.sk, 4);
        CHECK(0ull == d.Snap().full_bw);
    }


    /**
     * @brief RandBelow must be uniform (no modulo bias).
     *
     * 2^20 draws over 7 buckets through the production sampler: rejection
     * sampling gives every bucket the same probability, so each count must
     * land within 1% of 2^20/7. The old `SplitMix32 % 7` (a plain modulo over
     * a 2^32 range that is not a multiple of 7) skews the distribution and is
     * the red baseline this test pins.
     */
    void TestKccRandUnbiased() {
        constexpr UInt32 kDraws = 1u << 20;
        constexpr UInt32 kBuckets = 7;
        UInt32 counts[kBuckets] = {0};
        UInt32 state = 0x5EED1234u;
        for (UInt32 i = 0; i < kDraws; ++i) {
            const UInt32 r = xtcp::cc::KccTestRandBelow(&state, kBuckets);
            CHECK(r < kBuckets);
            ++counts[r];
        }
        const UInt32 expected = kDraws / kBuckets;
        UInt32 max_dev = 0;
        for (UInt32 b = 0; b < kBuckets; ++b) {
            const UInt32 dev = (counts[b] > expected) ? (counts[b] - expected)
                                                      : (expected - counts[b]);
            if (dev > max_dev) {
                max_dev = dev;
            }
        }
        CHECK(static_cast<UInt64>(max_dev) * 100 < static_cast<UInt64>(expected));
        std::fprintf(stderr, "rand buckets: %u %u %u %u %u %u %u (expected %u)\n",
                     counts[0], counts[1], counts[2], counts[3],
                     counts[4], counts[5], counts[6], expected);
        // n == 0 is a no-op that must not advance the state into garbage.
        CHECK(0u == xtcp::cc::KccTestRandBelow(&state, 0));
    }

    /**
     * @brief Production seeding must not be a predictable arithmetic
     *        progression (the old `seq * 2654435761 ^ 0x9E3779B9`).
     */
    void TestKccSeedUnpredictable() {
        xtcp::cc::KccTestResetRandom();   // production seeding
        Driver a;
        Driver b;
        Driver c;
        const UInt32 sa = a.Snap().rand_state;
        const UInt32 sb = b.Snap().rand_state;
        const UInt32 sc = c.Snap().rand_state;
        CHECK(sa != sb);
        CHECK(sb != sc);
        CHECK(sa != sc);
        // Not an arithmetic progression: the two deltas differ.
        const UInt32 d1 = sb - sa;
        const UInt32 d2 = sc - sb;
        CHECK(d1 != d2);
        // The counter component still decorrelates: seeds are not equal even
        // when the entropy repeats.
        CHECK(0 != sa || 0 != sb);
        xtcp::cc::KccTestSetRandomSeed(2);
    }
    /**
     * @brief Rejection BOUNDARY rows (a statistical test cannot see a
     *        1-in-6e8 off-by-one; these rows pin it exactly).
     *
     * For n = 7 the unbiased block is [0, 2^32 - 4) = [0, 4294967292).
     *   raw = limit - 1  -> accepted, bucket (limit-1) % 7
     *   raw = limit      -> REJECTED
     *   raw = 2^32 - 1   -> REJECTED
     * The old `0xFFFFFFFF - (0xFFFFFFFF % 7)` = 4294967292 with `r <= limit`
     * accepted limit itself, i.e. 4294967293 values - not a multiple of 7.
     */
    void TestKccRandRejectionBoundary() {
        constexpr UInt32 kN = 7;
        const UInt64 limit = xtcp::cc::KccTestRandLimit(kN);
        const UInt64 two32 = (UInt64(1) << 32);
        CHECK(limit == two32 - (two32 % kN));   // exact: 2^32 - 2^32 % n
        CHECK(0 == (limit % kN));               // a multiple of n
        CHECK(limit < two32);
        CHECK(two32 - limit == 4);              // 2^32 mod 7 == 4

        UInt32 bucket = 0xDEADBEEFu;
        CHECK(xtcp::cc::KccTestRandBelowFromRaw(limit - 1, kN, &bucket));
        CHECK(bucket == static_cast<UInt32>((limit - 1) % kN));
        // The exact boundary value must be REJECTED (the old code accepted it).
        CHECK(!xtcp::cc::KccTestRandBelowFromRaw(limit, kN, &bucket));
        CHECK(!xtcp::cc::KccTestRandBelowFromRaw(two32 - 1, kN, &bucket));
        // Accepted raws always map into range.
        for (UInt64 raw = 0; raw < limit; raw += 613566756ull) {
            CHECK(xtcp::cc::KccTestRandBelowFromRaw(raw, kN, &bucket));
            CHECK(bucket < kN);
        }
        // Degenerate bounds must terminate and be in range.
        CHECK(xtcp::cc::KccTestRandBelowFromRaw(0, 1, &bucket));
        CHECK(0u == bucket);
        CHECK(xtcp::cc::KccTestRandBelowFromRaw(0, 0, &bucket));
    }

    // ---- FSM-level tests: recorder CC + a real TcpConn ----
    RateSample g_recLast;
    UInt32 g_recCalls = 0;
    UInt32 g_recTxStart = 0;
    UInt32 g_recMarker = 0;
    Byte g_recCaState = 0;
    /**
     * @brief First non-zero rs->prior_in_flight of the current ACK.
     *
     * One ACK can emit several rate samples (the SACK-only one and the one
     * after the retransmission queue drains). The kernel's rs->prior_in_flight
     * describes the pipe BEFORE the ACK cleaned it, i.e. the first sample.
     * Reset this to 0 before delivering an ACK.
     */
    UInt64 g_recFirstPriorInflight = 0;

    void RecInit(XtcpConnCc*) noexcept {}
    void RecRelease(XtcpConnCc*) noexcept {}
    void RecControl(XtcpConnCc* sk, const RateSample* rs) noexcept {
        g_recLast = *rs;
        if (0 == g_recFirstPriorInflight && 0 != rs->prior_in_flight_bytes) {
            g_recFirstPriorInflight = rs->prior_in_flight_bytes;
        }
        g_recMarker = sk->app_limited;
        g_recCaState = sk->ca_state;
        ++g_recCalls;
    }
    void RecEvent(XtcpConnCc*, xtcp::cc::CaEvent ev) noexcept {
        if (xtcp::cc::kCaEventTxStart == ev) {
            ++g_recTxStart;
        }
    }

    void EnsureRecorderCc() {
        static bool registered = false;
        if (registered) {
            return;
        }
        XtcpCongestionOps ops;
        ops.name = "kcc_test_rec";
        ops.init = RecInit;
        ops.release = RecRelease;
        ops.cong_control = RecControl;
        ops.cwnd_event = RecEvent;
        CHECK(xtcp::cc::RegisterCongestionControl(ops));
        registered = true;
    }

    xtcp::core::Endpoint LocalEp() {
        xtcp::core::Endpoint e;
        e.family = 4;
        e.addr[0] = 0x0A000001;
        e.port = 443;
        return e;
    }
    xtcp::core::Endpoint RemoteEp() {
        xtcp::core::Endpoint e;
        e.family = 4;
        e.addr[0] = 0xC0A80102;
        e.port = 40000;
        return e;
    }

    std::vector<Byte> BuildSeg(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                               UInt16 flags, UInt16 window = 65535,
                               bool sack = false, UInt32 sl = 0, UInt32 sr = 0,
                               UInt32 payload_len = 0) {
        const UInt32 hdr = sack ? 32u : 20u;
        std::vector<Byte> seg(hdr + payload_len, 0);
        Byte* t = seg.data();
        t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
        t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = static_cast<Byte>(sack ? 0x80 : 0x50);
        t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                                  ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                                  ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                                  ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                                  ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00) |
                                  ((flags & xtcp::core::kFlagEce) ? 0x40 : 0x00));
        t[14] = static_cast<Byte>(window >> 8);
        t[15] = static_cast<Byte>(window & 0xFF);
        if (sack) {
            t[20] = 5;   // SACK kind
            t[21] = 10;  // length
            t[22] = static_cast<Byte>(sl >> 24); t[23] = static_cast<Byte>(sl >> 16);
            t[24] = static_cast<Byte>(sl >> 8);  t[25] = static_cast<Byte>(sl & 0xFF);
            t[26] = static_cast<Byte>(sr >> 24); t[27] = static_cast<Byte>(sr >> 16);
            t[28] = static_cast<Byte>(sr >> 8);  t[29] = static_cast<Byte>(sr & 0xFF);
            t[30] = 1; t[31] = 1;  // NOP padding
        }
        return seg;
    }

    struct FsmHarness {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn;
        xtcp::core::TimePoint now = 1000;

        explicit FsmHarness(xtcp::core::TcpState state = xtcp::core::TcpState::kEstablished)
            : conn(state, LocalEp(), RemoteEp(), 100, 200,
                   [this](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); }) {
            EnsureRecorderCc();
            conn.SetPeerMss(kMss);
            conn.SetCongestionControl("kcc_test_rec");
            g_recCalls = 0;
            g_recTxStart = 0;
            g_recMarker = 0;
        }

        void Send(UInt32 n) {
            // Size the payload buffer to the request: callers pass
            // multiples of the MSS (e.g. 4 * 1460 = 5840), which a fixed
            // 4096-byte stack array would overflow (ASan caught it).
            std::vector<Byte> buf(n, 0);
            CHECK(conn.SendData(buf.data(), n, now));
        }

        void Deliver(UInt32 ack, UInt16 flags = xtcp::core::kFlagAck,
                     UInt16 window = 65535, bool sack = false,
                     UInt32 sl = 0, UInt32 sr = 0, UInt32 seq = 201) {
            const std::vector<Byte> seg =
                BuildSeg(40000, 443, seq, ack, flags, window, sack, sl, sr);
            conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()), now);
        }

        void Warm() {
            Send(1460);
            now += 20000;
            Deliver(conn.SndNxt());
            CHECK(1 == g_recCalls);   // degenerate first sample
        }
    };

    /** @brief Delivers a raw ACK (optionally with one SACK block) to conn. */
    void DeliverRawAck(xtcp::core::TcpConn& conn, xtcp::core::TimePoint now, UInt32 ack,
                       UInt16 flags = xtcp::core::kFlagAck, bool sack = false,
                       UInt32 sl = 0, UInt32 sr = 0, UInt16 window = 65535) {
        const std::vector<Byte> seg = BuildSeg(40000, 443, 201, ack, flags, window, sack, sl, sr);
        conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()), now);
    }

    /**
     * @brief Raw segment with an RFC 7323 TSopt (plus optional MSS/SACK).
     *
     * BuildSeg above cannot carry timestamps, and the batch-2 Eifel tests need
     * to negotiate TSopt through a REAL SYN/SYN+ACK exchange (timestamps_ok_ is
     * only assigned on the handshake paths, tcp_fsm.cpp:4919 / :5118) and then
     * control the tsecr of the ACK under test.
     */
    std::vector<Byte> BuildSegTs(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                 UInt16 flags, UInt16 window, UInt32 ts_val, UInt32 ts_ecr,
                                 bool sack = false, UInt32 sl = 0, UInt32 sr = 0,
                                 bool mss_opt = false) {
        const UInt32 opt = (mss_opt ? 4u : 0u) + (sack ? 12u : 0u) + 12u;
        std::vector<Byte> seg(20 + opt, 0);
        Byte* t = seg.data();
        t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
        t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = static_cast<Byte>(((20 + opt) / 4) << 4);
        t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                                  ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                                  ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                                  ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                                  ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00) |
                                  ((flags & xtcp::core::kFlagEce) ? 0x40 : 0x00));
        t[14] = static_cast<Byte>(window >> 8);
        t[15] = static_cast<Byte>(window & 0xFF);
        UInt32 o = 20;
        if (mss_opt) {
            t[o] = 2; t[o + 1] = 4; t[o + 2] = 0x05; t[o + 3] = 0xB4;
            o += 4;
        }
        if (sack) {
            t[o] = 5; t[o + 1] = 10;
            t[o + 2] = static_cast<Byte>(sl >> 24); t[o + 3] = static_cast<Byte>(sl >> 16);
            t[o + 4] = static_cast<Byte>(sl >> 8);  t[o + 5] = static_cast<Byte>(sl & 0xFF);
            t[o + 6] = static_cast<Byte>(sr >> 24); t[o + 7] = static_cast<Byte>(sr >> 16);
            t[o + 8] = static_cast<Byte>(sr >> 8);  t[o + 9] = static_cast<Byte>(sr & 0xFF);
            t[o + 10] = 1; t[o + 11] = 1;
            o += 12;
        }
        t[o] = 8; t[o + 1] = 10;
        t[o + 2] = static_cast<Byte>(ts_val >> 24); t[o + 3] = static_cast<Byte>(ts_val >> 16);
        t[o + 4] = static_cast<Byte>(ts_val >> 8);  t[o + 5] = static_cast<Byte>(ts_val & 0xFF);
        t[o + 6] = static_cast<Byte>(ts_ecr >> 24); t[o + 7] = static_cast<Byte>(ts_ecr >> 16);
        t[o + 8] = static_cast<Byte>(ts_ecr >> 8);  t[o + 9] = static_cast<Byte>(ts_ecr & 0xFF);
        t[o + 10] = 1; t[o + 11] = 1;
        return seg;
    }

    /** @brief TSopt tsval of a stored IPv4 packet (0 when absent). */
    UInt32 TsvalOf(const xtcp::buf::BufRef& p) {
        if (p.IsEmpty()) {
            return 0;
        }
        const Byte* d = p.Data();
        const UInt32 ihl = static_cast<UInt32>(d[0] & 0x0F) * 4;
        if (p.Len() < ihl + 20) {
            return 0;
        }
        const UInt32 tcp_len = static_cast<UInt32>(d[ihl + 12] >> 4) * 4;
        for (UInt32 o = ihl + 20; o + 1 < ihl + tcp_len;) {
            const Byte kind = d[o];
            if (0 == kind || 1 == kind) {
                ++o;
                continue;
            }
            const Byte len = d[o + 1];
            if (8 == kind && 10 == len) {
                return (static_cast<UInt32>(d[o + 2]) << 24) |
                       (static_cast<UInt32>(d[o + 3]) << 16) |
                       (static_cast<UInt32>(d[o + 4]) << 8) |
                       static_cast<UInt32>(d[o + 5]);
            }
            if (len < 2) {
                break;
            }
            o += len;
        }
        return 0;
    }

    /**
     * @brief T2-1 (D03): the Eifel verdict must require the echoed TSval to be
     *        STRICTLY BEFORE the first retransmission's TSval.
     *
     * Kernel tcp_tsopt_ecr_before (tcp_input.c:2418-2422):
     *   saw_tstamp && rcv_tsecr && before(rcv_tsecr, when)
     * so an ACK for data sent AFTER the RTO (a NEWER tsecr) is a REAL loss and
     * must keep the cut. The old code undid on "tsecr != rto_ts_val_".
     *
     * The fixture negotiates TSopt through a real SYN/SYN+ACK exchange:
     * timestamps_ok_ is only assigned on the handshake paths, never by a
     * direct kEstablished construction.
     */
    void TestEifelRejectsNewerTsval() {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kSynSent, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSndBuf(4u << 20);
        xtcp::core::TimePoint now = 1000;
        conn.SendSyn();  // our SYN carries the TSopt offer (syn_ts_offered_)
        CHECK(1 == tx.size());
        const UInt32 our_syn_ts = TsvalOf(tx.back());
        CHECK(0 != our_syn_ts);
        // Peer's SYN+ACK also carries the TSopt -> timestamps_ok_ = true.
        const std::vector<Byte> synack = BuildSegTs(
            443, 40000, 500, 101,
            static_cast<UInt16>(xtcp::core::kFlagSyn | xtcp::core::kFlagAck), 65535,
            777, our_syn_ts, false, 0, 0, true);
        conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), now);
        CHECK(xtcp::core::TcpState::kEstablished == conn.State());

        for (UInt32 i = 0; i < 6; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        CHECK(6 * kMss == conn.SndInflight());
        // RTO: retransmits the front with a fresh TSval.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        const UInt32 cwnd_rto = conn.Cwnd();
        const UInt32 ssth_rto = conn.Ssthresh();
        const UInt32 rto_ts = TsvalOf(tx.back());
        CHECK(0 != rto_ts);
        // Cumulative ACK for the retransmitted segment, echoing a NEWER TSval
        // (data sent after the RTO) -> real loss, no undo.
        now += 20000;
        const UInt32 ack = conn.SndUna() + kMss;
        const std::vector<Byte> a = BuildSegTs(
            40000, 443, 201, ack, xtcp::core::kFlagAck, 65535, 888, rto_ts + 1000);
        conn.OnSegment(a.data(), static_cast<UInt32>(a.size()), now);
        std::fprintf(stderr,
                     "[T2-1] rto_ts=%u tsecr=%u | rto(cwnd=%u ssth=%u) -> after ACK "
                     "cwnd=%u ssth=%u\n",
                     rto_ts, rto_ts + 1000, cwnd_rto, ssth_rto, conn.Cwnd(), conn.Ssthresh());
        CHECK(conn.Ssthresh() <= ssth_rto);   // not undone
        CHECK(conn.Cwnd() <= cwnd_rto + 2);
    }

    /**
     * @brief A successful spurious-RTO undo must zero icsk_retransmits.
     *
     * Kernel tcp_try_undo_loss (tcp_input_66.c:2600-2610) runs
     *   icsk->icsk_retransmits = 0;
     * inside the undo branch, while tcp_undo_cwnd_reduction does not touch it.
     * Without the reset, every later timeout is still treated as "same loss
     * window" by tcp_enter_loss' guard and never cuts ssthresh again.
     *
     * Sequence: RTO -> spurious (older tsecr) -> undo. Then a NEW RTO after the
     * window advanced must cut ssthresh again.
     */
    void TestSpuriousRtoUndoResetsRetransmits() {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kSynSent, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSndBuf(4u << 20);
        xtcp::core::TimePoint now = 1000;
        conn.SendSyn();
        const UInt32 our_syn_ts = TsvalOf(tx.back());
        const std::vector<Byte> synack = BuildSegTs(
            443, 40000, 500, 101,
            static_cast<UInt16>(xtcp::core::kFlagSyn | xtcp::core::kFlagAck), 65535,
            777, our_syn_ts, false, 0, 0, true);
        conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), now);
        CHECK(xtcp::core::TcpState::kEstablished == conn.State());

        for (UInt32 i = 0; i < 10; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 cwnd_pre = conn.Cwnd();
        // RTO #1, then an ACK echoing an OLDER TSval -> spurious -> undo.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        const UInt32 rto_ts = TsvalOf(tx.back());
        CHECK(0 != rto_ts);
        now += 20000;
        const UInt32 ack1 = conn.SndUna() + kMss;
        const std::vector<Byte> a1 = BuildSegTs(
            40000, 443, 201, ack1, xtcp::core::kFlagAck, 65535, 888, rto_ts - 1);
        conn.OnSegment(a1.data(), static_cast<UInt32>(a1.size()), now);
        std::fprintf(stderr, "[spurious-rto] pre=%u after undo cwnd=%u ssth=%u\n",
                     cwnd_pre, conn.Cwnd(), conn.Ssthresh());
        CHECK(conn.Cwnd() + 2 >= cwnd_pre);   // the undo restored the window
        const UInt32 ssth_after_undo = conn.Ssthresh();

        // The ACK advanced snd_una past high_seq, so a new loss window opens.
        // A fresh RTO must therefore cut ssthresh again - unless the undo left
        // icsk_retransmits set, in which case the guard suppresses the cut.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        std::fprintf(stderr, "[spurious-rto] next RTO ssth=%u (was %u)\n",
                     conn.Ssthresh(), ssth_after_undo);
        // The cut happened. Note: the ACK above also advanced snd_una, which
        // clears icsk_retransmits on its own (kernel tcp_clear_retrans), so
        // this assertion guards the END-TO-END behaviour rather than the
        // single reset inside the undo branch (that one is a faithful copy of
        // tcp_try_undo_loss and is currently redundant on this path).
        CHECK(conn.Ssthresh() < ssth_after_undo);
    }

    /**
     * @brief T2-2 (D04): a no-TSopt RTO must still be ADJUDICATED by a
     *        cumulative ACK that covers the retransmitted range, so the sticky
     *        `rto_pending_` can no longer disable the D-SACK undo forever.
     *
     * Kernel tcp_packet_delayed (tcp_input.c:2437-2441) needs TSopt evidence
     * the port never has (data segments omit TSopt by design), so the verdict
     * is "real loss" - but it IS a verdict, and tcp_may_undo's
     * `!tp->undo_retrans || tcp_packet_delayed(tp)` then reopens the D-SACK
     * path (tcp_try_undo_dsack, tcp_input.c:2580-2593).
     *
     * The primary observable is therefore the VERDICT ITSELF (RtoPending()),
     * not a window number: on HEAD the flag is never cleared without TSopt, so
     * it stays true for the rest of the connection's life. The D-SACK half is
     * checked on the same ACK (before/after) so ordinary ACK-clock growth
     * cannot mask or fake it.
     */
    void TestDsackUndoAfterRtoWithoutTsopt() {
        FsmHarness h;   // no SetPeerTimestampsOffered -> timestamps_ok_ = false
        // Reno: the recorder CC the harness installs owns cwnd through its
        // cong_control hook, so the window would not regrow between the two
        // episodes. The D-SACK undo restores prior_cwnd_, which must be
        // observably larger than the cut (a4probe35 uses a plain Reno conn).
        CHECK(h.conn.SetCongestionControl(""));
        h.conn.SetSackOk(true);
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 r = 0; r < 8; ++r) {
            const UInt32 cwnd = h.conn.Cwnd();
            for (UInt32 i = 0; i < cwnd; ++i) {
                h.Send(kMss);
            }
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
        }
        const UInt32 cwnd_pre = h.conn.Cwnd();
        // Episode 1: RTO (no TSopt anywhere on this connection).
        h.Send(kMss);
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        const UInt32 cwnd_rto = h.conn.Cwnd();
        const bool pending_at_rto = h.conn.RtoPending();
        // The covering ACK answers the "spurious?" question: real loss.
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        const bool pending_after_ack = h.conn.RtoPending();
        std::fprintf(stderr,
                     "[T2-2] warm cwnd=%u | after RTO cwnd=%u rto_pending=%d | after covering "
                     "ACK cwnd=%u rto_pending=%d\n",
                     cwnd_pre, cwnd_rto, pending_at_rto ? 1 : 0, h.conn.Cwnd(),
                     pending_after_ack ? 1 : 0);
        CHECK(pending_at_rto);            // the RTO armed a verdict window
        CHECK(!pending_after_ack);        // HEAD: sticky true (D04)

        // Second half: the D-SACK undo must be able to fire afterwards. The
        // comparison is the SAME ACK's before/after window, so ACK-clock growth
        // from earlier ACKs cannot be mistaken for an undo.
        for (UInt32 r = 0; r < 40; ++r) {
            const UInt32 cwnd = h.conn.Cwnd();
            for (UInt32 i = 0; i < cwnd; ++i) {
                h.Send(kMss);
            }
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
        }
        for (UInt32 i = 0; i < 3; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);
        }
        CHECK(h.conn.FastRecovery());
        const UInt32 cwnd_cut = h.conn.Cwnd();
        const UInt32 ssth_cut = h.conn.Ssthresh();
        // D-SACK covering the retransmitted range (block end == ACK).
        h.now += 1000;
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true, una, una + kMss);
        const UInt32 cwnd_dsack = h.conn.Cwnd();
        const bool fr_after = h.conn.FastRecovery();
        const UInt32 high_after = h.conn.HighSeq();
        std::fprintf(stderr,
                     "[T2-2] cut cwnd=%u ssth=%u -> after D-SACK cwnd=%u ssth=%u "
                     "fast_recovery=%d high_seq=%u\n",
                     cwnd_cut, ssth_cut, cwnd_dsack, h.conn.Ssthresh(),
                     fr_after ? 1 : 0, high_after);
        // The D-SACK undo closes the episode: kernel tcp_try_undo_dsack ->
        // tcp_undo_cwnd_reduction -> tcp_try_keep_open (tcp_input.c:2580-2593).
        // HEAD leaves the recovery open (fr=1, high_seq intact) because the
        // sticky rto_pending_ keeps the gate at :2699 closed.
        CHECK(!fr_after);
        CHECK(0u == high_after);
        CHECK(cwnd_dsack > cwnd_cut);          // D-SACK undo fired
        CHECK(ssth_cut <= h.conn.Ssthresh());  // not re-cut (weak guard)
    }

    /**
     * @brief Loss-mark probe CC for T2-3.
     *
     * The observable MUST NOT be the undo_cwnd hook: HEAD's exit branch is an
     * inline `cc_.snd_cwnd = prior_cwnd_` (no hook call anywhere in the HEAD
     * tcp_fsm.cpp), so a hook counter reads 0 on both sides and cannot be red.
     *
     * Instead the ssthresh hook hands out DIFFERENT finite marks per call: the
     * RTO's cut (first call) leaves a large mark, the later no-SACK entry saves
     * it as prior_ssthresh_ and cuts to a smaller one. An undo restores
     * prior_ssthresh_ (the larger value, kernel tcp_undo_cwnd_reduction
     * tcp_input.c:2515-2523); a refused undo leaves the smaller mark.
     */
    UInt32 g_b2SsthCalls = 0;
    UInt32 B2FiniteSsthresh(XtcpConnCc*) noexcept {
        ++g_b2SsthCalls;
        return (1 == g_b2SsthCalls) ? 8u : 3u;
    }

    /**
     * @brief T2-3 (D05): do not undo while retransmissions are still in
     *        flight - their D-SACKs may yet prove the cut was wrong.
     *
     * Kernel tcp_may_undo (tcp_input.c:2530-2533) with undo_retrans > 0 and no
     * TSopt evidence refuses; the port expressed that as `undo_retrans_ <= 0`.
     */
    void TestNoUndoWhileRetransInFlight() {
        static bool registered = false;
        if (!registered) {
            XtcpCongestionOps ops;
            ops.name = "b2_finite_ssth";
            ops.ssthresh = B2FiniteSsthresh;   // finite loss marks -> restore visible
            CHECK(xtcp::cc::RegisterCongestionControl(ops));
            registered = true;
        }
        FsmHarness h;
        CHECK(h.conn.SetCongestionControl("b2_finite_ssth"));
        h.conn.SetSackOk(false);   // no-SACK entry -> undo_marker_ = true on HEAD
        h.conn.SetSndBuf(4u << 20);
        g_b2SsthCalls = 0;
        for (UInt32 i = 0; i < 8; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        // RTO: one retransmission goes out and its ACK never arrives, so
        // retrans_out > 0 when the next episode is entered.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        CHECK(0 < h.conn.RetransmitCount());
        const UInt32 cwnd_rto = h.conn.Cwnd();
        // A NEW no-SACK entry while that retransmission is still in flight:
        // CutCwnd records undo_retrans_ > 0 (kernel tcp_init_undo's
        // `retrans_out ?: -1`, tcp_input.c:2106-2111).
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);
        }
        CHECK(h.conn.FastRecovery());
        // Precondition (the point of this test): a retransmission was still in
        // flight when the episode was entered. Observed through the
        // retransmission counter, not UndoRetrans(): HEAD never writes that
        // field (it stays at its -1 initializer), so asserting on it would make
        // the red case fail for a missing field instead of for behaviour.
        CHECK(0 < h.conn.RetransmitCount());
        const UInt32 cwnd_cut = h.conn.Cwnd();
        const UInt32 ssth_cut = h.conn.Ssthresh();
        CHECK(ssth_cut < 8u);   // the entry cut to the smaller mark
        // Push snd_nxt above high_seq_ so the exit ACK takes the part-D branch
        // instead of Reno's hold-at-high_seq (tcp_is_non_sack_preventing_reopen,
        // tcp_input.c:2535-2548).
        h.Send(kMss);
        // Clean cumulative ACK above high_seq_ ends the recovery: it must NOT
        // restore the window/ssthresh.
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        const UInt32 ssth_after = h.conn.Ssthresh();
        std::fprintf(stderr,
                     "[T2-3] after RTO cwnd=%u | entry cwnd=%u ssth=%u -> "
                     "after exit ACK cwnd=%u ssth=%u\n",
                     cwnd_rto, cwnd_cut, ssth_cut, h.conn.Cwnd(), ssth_after);
        // No undo: the entry's loss mark stands. HEAD restores prior_ssthresh_
        // (the RTO's larger mark) through the inline assignment.
        CHECK(ssth_cut == ssth_after);
    }

    /**
     * @brief T2-4 (D05, the missing INCREMENT): a retransmission the episode
     *        itself emits must count against undo_retrans, so the clean exit
     *        cannot undo a REAL loss.
     *
     * Kernel tcp_output_66.c:3390-3392 (inside tcp_retransmit_skb, i.e. every
     * retransmission actually put on the wire):
     *     if (tp->undo_retrans < 0) tp->undo_retrans = 0;
     *     tp->undo_retrans += tcp_skb_pcount(skb);
     * together with the entry assignment `undo_retrans = retrans_out ?: -1`
     * (tcp_input.c:2110). A no-SACK dup-ACK entry runs tcp_init_undo BEFORE the
     * fast retransmit, so the entry value is -1 and only the increment makes the
     * counter positive - which is exactly what makes tcp_may_undo
     * (tcp_input.c:2530-2533) refuse the undo without TSopt evidence.
     *
     * Fixture: no prior RTO (retrans_out == 0 at entry), then the entry's own
     * fast retransmit goes out, then a clean ACK above high_seq_ ends the
     * recovery. The window must collapse to ssthresh, not be restored.
     */
    void TestNoUndoWhenOwnRetransmitCounts() {
        static bool registered = false;
        if (!registered) {
            XtcpCongestionOps ops;
            ops.name = "b2_own_retx";
            ops.ssthresh = B2FiniteSsthresh;   // finite marks 8 then 3
            CHECK(xtcp::cc::RegisterCongestionControl(ops));
            registered = true;
        }
        FsmHarness h;
        CHECK(h.conn.SetCongestionControl("b2_own_retx"));
        h.conn.SetSackOk(false);   // no-SACK entry -> undo candidate
        h.conn.SetSndBuf(4u << 20);
        g_b2SsthCalls = 0;
        for (UInt32 i = 0; i < 8; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        const UInt32 retx_before = h.conn.RetransmitCount();
        // No RTO here: retrans_out == 0 at the entry, so the entry value is the
        // kernel's -1 and ONLY the increment can make it positive.
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);
        }
        CHECK(h.conn.FastRecovery());
        // The entry's own fast retransmit actually went out.
        const UInt32 retx_after = h.conn.RetransmitCount();
        CHECK(retx_before < retx_after);
        const UInt32 cwnd_cut = h.conn.Cwnd();
        const UInt32 ssth_cut = h.conn.Ssthresh();
        // Push snd_nxt above high_seq_ so the exit ACK takes the part-D branch
        // (not Reno's hold-at-high_seq).
        h.Send(kMss);
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        std::fprintf(stderr,
                     "[T2-4] retx %u -> %u | entry cwnd=%u ssth=%u -> after exit ACK "
                     "cwnd=%u ssth=%u\n",
                     retx_before, retx_after, cwnd_cut, ssth_cut,
                     h.conn.Cwnd(), h.conn.Ssthresh());
        // No undo: the episode's own retransmission counts, so the cut stands.
        // The observable is ssthresh, not cwnd: the same ACK also runs
        // tcp_cong_control with the state already Open, so slow start grows cwnd
        // on top of the collapse (kernel tcp_input.c:3939-3941).
        CHECK(ssth_cut == h.conn.Ssthresh());
    }

    /**
     * @brief KCC with a recording wrapper: the real plugin's behaviour plus
     *        the icsk_ca_state observed at the cong_control hook.
     */
    const XtcpCongestionOps* g_kccOps = NULLPTR;

    void KccRecInit(XtcpConnCc* sk) noexcept {
        if (NULLPTR != g_kccOps && NULLPTR != g_kccOps->init) {
            g_kccOps->init(sk);
        }
    }
    void KccRecRelease(XtcpConnCc* sk) noexcept {
        if (NULLPTR != g_kccOps && NULLPTR != g_kccOps->release) {
            g_kccOps->release(sk);
        }
    }
    UInt32 KccRecSsthresh(XtcpConnCc* sk) noexcept {
        return (NULLPTR != g_kccOps && NULLPTR != g_kccOps->ssthresh)
            ? g_kccOps->ssthresh(sk) : sk->snd_ssthresh;
    }
    void KccRecSetState(XtcpConnCc* sk, Byte new_state) noexcept {
        if (NULLPTR != g_kccOps && NULLPTR != g_kccOps->set_state) {
            g_kccOps->set_state(sk, new_state);
        }
    }
    void KccRecEvent(XtcpConnCc* sk, xtcp::cc::CaEvent ev) noexcept {
        if (NULLPTR != g_kccOps && NULLPTR != g_kccOps->cwnd_event) {
            g_kccOps->cwnd_event(sk, ev);
        }
    }
    UInt32 KccRecUndo(XtcpConnCc* sk) noexcept {
        return (NULLPTR != g_kccOps && NULLPTR != g_kccOps->undo_cwnd)
            ? g_kccOps->undo_cwnd(sk) : sk->snd_cwnd;
    }
    void KccRecControl(XtcpConnCc* sk, const RateSample* rs) noexcept {
        g_recCaState = sk->ca_state;
        ++g_recCalls;
        if (NULLPTR != g_kccOps && NULLPTR != g_kccOps->cong_control) {
            g_kccOps->cong_control(sk, rs);
        }
    }

    void EnsureKccRecorder() {
        static bool registered = false;
        if (registered) {
            return;
        }
        xtcp::cc::RegisterKcc();
        g_kccOps = xtcp::cc::FindCongestionControl("kcc");
        CHECK(NULLPTR != g_kccOps);
        XtcpCongestionOps ops;
        ops.name = "kcc_test_rec_fwd";
        ops.init = KccRecInit;
        ops.release = KccRecRelease;
        ops.ssthresh = KccRecSsthresh;
        ops.set_state = KccRecSetState;
        ops.cwnd_event = KccRecEvent;
        ops.undo_cwnd = KccRecUndo;
        ops.cong_control = KccRecControl;
        CHECK(xtcp::cc::RegisterCongestionControl(ops));
        registered = true;
    }

    /**
     * @brief "KCC shape" probe for the flush-order test: ssthresh passes the
     *        sentinel through (like KccSsthresh) and cong_control owns the
     *        window (pins it to 1 whenever the CA state is Open). The window
     *        the FSM leaves behind at the exit is therefore observable in the
     *        flush that follows.
     */
    UInt32 KccShapeSsthresh(XtcpConnCc* sk) noexcept {
        return sk->snd_ssthresh;
    }
    void KccShapeControl(XtcpConnCc* sk, const RateSample*) noexcept {
        if (0 == sk->ca_state) {
            sk->snd_cwnd = 1;
        }
    }

    /** Finite-threshold variant: the plugin keeps its own (rate-based) window
     *  and only uses snd_ssthresh as a loss mark. */
    UInt32 KccShapeFiniteSsthresh(XtcpConnCc*) noexcept {
        return 3;
    }
    UInt32 g_recCwndAtHook = 0;
    UInt32 g_recCompleteCwr = 0;
    void KccShapeRecordOnly(XtcpConnCc* sk, const RateSample*) noexcept {
        g_recCwndAtHook = sk->snd_cwnd;
        ++g_recCalls;
    }
    void KccShapeEvent(XtcpConnCc*, xtcp::cc::CaEvent ev) noexcept {
        if (xtcp::cc::kCaEventCompleteCwr == ev) {
            ++g_recCompleteCwr;
        }
    }

    /**
     * @brief D01 (main red case): a rate-based CC (cong_control) owns the
     *        window when a cwnd-reduction episode ends.
     *
     * Kernel tcp_end_cwnd_reduction (tcp_input.c:2669-2683) opens with
     *   if (icsk_ca_ops->cong_control) return;
     * so the FSM must not write `cwnd = ssthresh` for KCC/BBR, and must not
     * dispatch CA_EVENT_COMPLETE_CWR either. KCC's ssthresh hook passes the
     * current snd_ssthresh through (cc_kcc.cpp:1042), which is the
     * 0x7FFFFFFF "unlimited" sentinel until DRAIN computes a BDP target, so
     * the unconditional exit write handed KCC a 0x7FFFFFFF window (audit
     * D01). The CA state must already be Open when the CC hook runs (kernel
     * runs tcp_fastretrans_alert before tcp_cong_control).
     *
     * No warmup on purpose: once KccMain has a min_rtt sample its BDP clamp
     * (cc_kcc.cpp:976-996) rewrites the sentinel, which would mask the
     * defect. The no-RTT connection is exactly the shape the kernel guard
     * protects (audit D01, a4probe37).
     */
    void TestKccRecoveryExitKeepsPriorCwnd() {
        EnsureKccRecorder();
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(4u << 20);
        CHECK(conn.SetCongestionControl("kcc_test_rec_fwd"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 4; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 cwnd_pre = conn.Cwnd();
        CHECK(0x7FFFFFFFu == conn.Ssthresh());     // KCC on the sentinel
        const UInt32 una = conn.SndUna();
        // Three SACK dup-ACKs with a REAL gap: SACK-confirmed entry
        // (undo_marker_ stays false, so the exit cannot undo).
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true,
                          una + kMss, una + 2 * kMss);
        }
        CHECK(conn.FastRecovery());
        CHECK(conn.Cwnd() < cwnd_pre);             // the entry cut the window
        g_recCalls = 0;
        g_recCaState = 0xFF;
        now += 20000;
        DeliverRawAck(conn, now, conn.SndNxt());
        CHECK(!conn.FastRecovery());
        CHECK(1 <= g_recCalls);
        CHECK(0u == g_recCaState);                 // state Open before the CC hook
        CHECK(conn.Cwnd() < 0x1000u);              // red: 0x7FFFFFFF (D01)
        CHECK(0 < conn.Cwnd());                    // a legal window
    }

    /**
     * @brief D01 (second guard): a cong_control CC with a FINITE ssthresh.
     *
     * Kernel tcp_end_cwnd_reduction (tcp_input.c:2673-2674) returns before
     * touching cwnd when the algorithm installs cong_control, so the window
     * the CC owns survives the episode end. The dfe0b55 exit block wrote
     * `cwnd = ssthresh` unconditionally, collapsing the rate-based window to
     * the threshold the plugin only uses as a loss mark (KccSsthresh passes
     * it through, cc_kcc.cpp:1042). The kernel also skips
     * tcp_ca_event(CA_EVENT_COMPLETE_CWR) on that path.
     */
    void TestKccRecoveryExitKeepsCcWindow() {
        static bool registered = false;
        if (!registered) {
            XtcpCongestionOps ops;
            ops.name = "kcc_test_fin_ssth";
            ops.ssthresh = KccShapeFiniteSsthresh;
            ops.cong_control = KccShapeRecordOnly;
            ops.cwnd_event = KccShapeEvent;
            CHECK(xtcp::cc::RegisterCongestionControl(ops));
            registered = true;
        }
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(4u << 20);
        CHECK(conn.SetCongestionControl("kcc_test_fin_ssth"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 10; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true,
                          una + kMss, una + 2 * kMss);
        }
        CHECK(conn.FastRecovery());
        const UInt32 cwnd_cut = conn.Cwnd();
        CHECK(3u == conn.Ssthresh());        // the probe's finite threshold
        CHECK(cwnd_cut > conn.Ssthresh());   // rate-based window != threshold
        g_recCalls = 0;
        g_recCwndAtHook = 0;
        g_recCompleteCwr = 0;
        now += 20000;
        DeliverRawAck(conn, now, conn.SndNxt());
        CHECK(!conn.FastRecovery());
        CHECK(1 <= g_recCalls);
        std::fprintf(stderr, "[d01-fin-ssth] cut=%u ssth=%u hook_cwnd=%u exit=%u\n",
                     cwnd_cut, conn.Ssthresh(), g_recCwndAtHook, conn.Cwnd());
        // Red: the hook saw cwnd=3 (the FSM had already collapsed it).
        CHECK(cwnd_cut == g_recCwndAtHook);
        CHECK(cwnd_cut == conn.Cwnd());
        CHECK(0 == g_recCompleteCwr);        // kernel: no event on this path
    }

    /**
     * @brief D01 (flush order): the buffered sends of the exit ACK must ride
     *        the window the CC left behind, not the FSM's exit write.
     *
     * Kernel send order is tcp_rate_gen -> tcp_cong_control ->
     * tcp_xmit_recovery (tcp_input.c:3938-3940): data leaves AFTER the CC has
     * had its say. The port flushed at the top of the exit block, so one exit
     * ACK released the whole backlog against the 0x7FFFFFFF window the block
     * had just written (audit D01, a4probe27: 6 segments).
     */
    void TestExitAckDoesNotBurst() {
        static bool registered = false;
        if (!registered) {
            // KCC-shaped probe: ssthresh passthrough (sentinel) + a
            // cong_control that pins cwnd to 1 the moment it sees the state
            // leave Recovery - the strongest possible "the CC owns cwnd".
            XtcpCongestionOps ops;
            ops.name = "kcc_test_shape";
            ops.ssthresh = KccShapeSsthresh;
            ops.cong_control = KccShapeControl;
            CHECK(xtcp::cc::RegisterCongestionControl(ops));
            registered = true;
        }
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(4u << 20);
        CHECK(conn.SetCongestionControl("kcc_test_shape"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 10; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true,
                          una + kMss, una + 2 * kMss);
        }
        CHECK(conn.FastRecovery());
        CHECK(0 < conn.Cwnd());
        // Backlog: the recovery pipe gate buffers these instead of sending.
        for (UInt32 i = 0; i < 40; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const size_t tx_before = tx.size();
        now += 20000;
        DeliverRawAck(conn, now, conn.SndNxt());
        const size_t burst = tx.size() - tx_before;
        std::fprintf(stderr, "[d01-flush] burst=%zu cwnd=%u\n", burst, conn.Cwnd());
        CHECK(burst <= 2);   // red: 6 (flush ran before the CC hook)
        CHECK(1u == conn.Cwnd());   // the CC's window survived the flush
    }

    void TestKccFsmDelayedFields() {
        {
            // Single sub-MSS segment, clean ACK: delayed.
            FsmHarness h;
            h.Warm();
            g_recCalls = 0;
            h.Send(100);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(1 == g_recCalls);
            CHECK(g_recLast.is_ack_delayed);
            CHECK(1460ull == g_recLast.prior_delivered);
            CHECK(1560ull == g_recLast.delivered_total);
            CHECK(1u == g_recLast.is_app_limited);
            CHECK(0u == g_recMarker);   // cleared before the sample
        }
        {
            // Full MSS ACK: strict '< mss' fails.
            FsmHarness h;
            h.Warm();
            h.Send(1460);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // Two popped segments: pkts_acked != 1.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.Send(100);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // RTO retransmission: TCPCB_RETRANS equivalent excludes it.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.now += 2000000;
            h.conn.OnRetransmitTimer(h.now);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // ECE (FLAG_CA_ALERT).
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt(),
                      static_cast<UInt16>(xtcp::core::kFlagAck | xtcp::core::kFlagEce));
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // Any SACK block on the ACK.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.now += 20000;
            const UInt32 end = h.conn.SndNxt();
            h.Deliver(end, xtcp::core::kFlagAck, 65535, true, end, end + 100);
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // Entry-level prior_sacked: the segment that was SACKed earlier
            // is cumulatively ACKed by a SACK-less ACK.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            const UInt32 mid = h.conn.SndNxt();
            h.Send(100);
            h.now += 20000;
            h.Deliver(mid, xtcp::core::kFlagAck, 65535, true, mid, mid + 100);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // TLP re-sends the tail without touching the retry budget.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.now += 50000;
            h.conn.OnPoll(h.now);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // Persist re-probe of unacked data is a retransmission.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.Deliver(h.conn.SndUna(), xtcp::core::kFlagAck, 0);  // zero window
            h.Send(100);                                          // arms persist
            h.now += 1100000;
            h.conn.OnPoll(h.now);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(!g_recLast.is_ack_delayed);
        }
        {
            // Persist NEW byte (no unacked data): ordinary single-byte ACK.
            FsmHarness h;
            h.Warm();
            h.Deliver(h.conn.SndUna(), xtcp::core::kFlagAck, 0);  // zero window
            h.Send(100);                                          // buffered + persist armed
            h.now += 1100000;
            h.conn.OnPoll(h.now);                                 // consumes 1 new byte
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(g_recLast.is_ack_delayed);
        }
    }

    void TestKccFsmTxStartAndAppLimited() {
        FsmHarness h;
        CHECK(0 == g_recTxStart);
        h.Send(100);
        CHECK(1 == g_recTxStart);       // idle pipe -> TX_START once
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        CHECK(g_recLast.is_app_limited);  // send-time snapshot of the marker
        // Kernel tcp_rate_gen clears with after(tp->delivered, app_limited).
        // The marker latched at the send entry is (0 + 0) encoded as 1, so a
        // single delivered packet (delivered == 1) does NOT clear it yet -
        // kernel semantics. The SECOND delivery passes it.
        CHECK(1u == g_recMarker);
        h.Send(100);
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        CHECK(0u == g_recMarker);         // cleared once delivered passes it
        // The second send happened on an empty pipe (the first ACK emptied
        // it), so it is a fresh TX_START.
        CHECK(2 == g_recTxStart);
    }

    /**
     * @brief Every CC path must leave snd_cwnd a LEGAL window.
     *
     * Regression for the KCC fast-recovery entry: KccSsthresh passes the
     * current ssthresh through (0x7FFFFFFF, the "unlimited" sentinel), so
     * the RFC 5681 `cwnd = ssthresh + 3` inflation - which belongs to the
     * classic Reno path only - produced 0x80000002 (2^31+2). No kernel value
     * is legal there (tcp_snd_cwnd_clamp is <= 0x7FFFFFFF, and the kernel's
     * plugin path enters recovery through tcp_cwnd_reduction instead).
     * Observed red on test_reorder_gate: "cwnd 16->2147483650".
     */
    void TestKccFsmCwndStaysLegal() {
        xtcp::cc::RegisterKcc();
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        CHECK(conn.SetCongestionControl("kcc"));
        xtcp::core::TimePoint now = 1000;
        Byte data[8192];
        std::memset(data, 0x33, sizeof(data));
        CHECK(conn.SendData(data, sizeof(data), now));
        CHECK(conn.Cwnd() <= 0x7FFFFFFFu);

        // Three dup-ACKs whose SACK block reveals a REAL gap: fast recovery
        // fires (the reordering gate does not apply to confirmed gaps).
        const UInt32 una = conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            const std::vector<Byte> ack =
                BuildSeg(40000, 443, 201, una, xtcp::core::kFlagAck, 65535, true,
                         una + 1460, una + 2920);
            conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), now);
            CHECK(0 < conn.Cwnd());
            CHECK(conn.Cwnd() <= 0x7FFFFFFFu);   // red: 0x80000002 before the fix
        }

        // RTO path: the plugin branch keeps CutCwnd's packets_in_flight + 1
        // (the kernel tcp_enter_loss tail); it must never collapse to an
        // illegal or zero window either.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        CHECK(0 < conn.Cwnd());
        CHECK(conn.Cwnd() <= 0x7FFFFFFFu);
    }

    /**
     * @brief The CA state must return to Open when a recovery episode ends.
     *
     * Kernel tcp_fastretrans_alert ends the episode once snd_una reaches
     * high_seq (tp->snd_nxt at the entry) and calls tcp_set_ca_state(
     * TCP_CA_Open) BEFORE tcp_cong_control (the CC hook). The port kept
     * ca_state at Recovery/Loss forever, so a state-keying CC (KCC's
     * kcc_set_cwnd_to_recover_or_restore) saw "Recovery entered" on every
     * later ACK and re-cut the window to inflight+acked - the window could
     * never recover. Red baseline: cwnd stayed 4 and ca_state stayed 3
     * (observed as test_fastrec_undo "cwnd_before <= cwnd_after" on CI).
     */
    void TestKccFsmCaStateReturnsToOpen() {
        FsmHarness h;
        // SACK is negotiated: kernel tcp_is_non_sack_preventing_reopen
        // (tcp_input.c:2535-2548) holds a NON-SACK recovery at exactly
        // high_seq, while SACK is safe to reopen there. This case pins the
        // reopen + state transition, so it must run the SACK variant.
        h.conn.SetSackOk(true);
        h.Send(kMss);
        h.Send(kMss);
        h.Send(kMss);
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        const UInt32 end = h.conn.SndNxt();
        const UInt32 cwnd_before = h.conn.Cwnd();
        // Three RAW dup-ACKs (no SACK blocks) advertising a ZERO window: the
        // no-SACK entry still arms undo_marker_, but RetransmitEarliestMissing
        // skips the transmit (RFC 1122 s4.2.2.17, tcp_fsm.cpp's `0 == snd_wnd_`
        // early return), so no retransmission is put on the wire and
        // undo_retrans stays -1. That is the kernel's "Happy end! We did not
        // retransmit anything" case (tcp_input.c:2558-2560) where tcp_may_undo
        // legitimately allows the undo; with a real retransmission in flight
        // tcp_may_undo refuses without TSopt evidence (tcp_input.c:2530-2533 +
        // tcp_output_66.c:3390-3392).
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una, xtcp::core::kFlagAck, 0);
        }
        CHECK(h.conn.FastRecovery());          // recovery active
        // The cumulative ACK covers everything up to high_seq: the episode
        // ends and the state must be Open when the CC hook runs.
        g_recCalls = 0;
        g_recCaState = 0xFF;
        h.now += 20000;
        h.Deliver(end);
        CHECK(1 == g_recCalls);
        CHECK(0u == g_recCaState);             // red: 3 (Recovery) before the fix
        CHECK(!h.conn.FastRecovery());
        CHECK(cwnd_before <= h.conn.Cwnd());   // window not re-cut by the CC
    }

    /**
     * @brief Kernel tcp_is_non_sack_preventing_reopen (tcp_input.c:2535-2548):
     *        a NON-SACK recovery is held at exactly high_seq - reopening there
     *        lets the very next dup-ACK start a false fast retransmit
     *        (RFC 2582). tcp_try_undo_recovery returns true in that case
     *        (tcp_input.c:2572-2573), so tcp_fastretrans_alert part D returns
     *        immediately (tcp_input.c:3015-3016) and the port's PRR block must
     *        not close the episode either.
     *
     *        The CC hook still runs afterwards: tcp_cong_control is called
     *        unconditionally by tcp_ack (tcp_input.c:3939), and with the state
     *        still Recovery it takes tcp_cwnd_reduction (PRR) - it must NOT
     *        take tcp_cong_avoid, i.e. it must not raise ssthresh/cwnd in
     *        congestion avoidance.
     */
    void TestNonSackRecoveryHoldsAtHighSeq() {
        FsmHarness h;              // recorder CC: no ssthresh hook (Reno path)
        h.conn.SetSackOk(false);   // kernel tcp_is_reno(tp)
        h.Send(kMss);
        h.Send(kMss);
        h.Send(kMss);
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        const UInt32 end = h.conn.SndNxt();
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);   // raw dup-ACK: no-SACK recovery entry
        }
        CHECK(h.conn.FastRecovery());
        CHECK(0x7FFFFFFFu != h.conn.Ssthresh());   // the entry recorded a cut
        const UInt32 cwnd_cut = h.conn.Cwnd();
        // ACK exactly at high_seq: HELD, but the undo must have run first
        // (kernel tcp_input.c:2555-2573).
        g_recCalls = 0;
        g_recCaState = 0xFF;
        h.now += 20000;
        h.Deliver(end);
        CHECK(1 <= g_recCalls);
        CHECK(3u == g_recCaState);                 // still Recovery at the hook
        CHECK(h.conn.FastRecovery());
        // The undo could not run (a retransmission is still in flight), so the
        // cut window stands above ssthresh.
        CHECK(h.conn.Cwnd() > h.conn.Ssthresh());
        // Batch 4 (D08): this harness CC is a cong_control algorithm, so the
        // kernel's tcp_cong_control returns EARLY (tcp_input.c:3518-3521) and
        // tcp_cwnd_reduction is never called: the FSM must NOT rewrite the
        // window on this ACK. Pre-D08 the byte-domain PRR block did rewrite it
        // (1462 = ssthresh 2 + 1460 acked bytes), which is exactly the defect.
        // The window must therefore still be the value the entry produced.
        CHECK(h.conn.Cwnd() == cwnd_cut);
        std::fprintf(stderr, "[hold-reno] cwnd=%u ssth=%u\n",
                     h.conn.Cwnd(), h.conn.Ssthresh());
        // The ACK above high_seq (new data sent after the held ACK) ends it.
        h.Send(kMss);
        CHECK(xtcp::core::SeqLt(end, h.conn.SndNxt()));
        g_recCalls = 0;
        g_recCaState = 0xFF;
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        CHECK(1 <= g_recCalls);
        CHECK(0u == g_recCaState);
        CHECK(!h.conn.FastRecovery());
    }

    /**
     * @brief Kernel tcp_process_loss (tcp_input_66.c:2845-2885) calls
     *        tcp_try_undo_recovery (tcp_input_66.c:2551-2577) when snd_una
     *        reaches high_seq in CA_Loss. tcp_try_undo_recovery holds the
     *        state via tcp_is_non_sack_preventing_reopen (tcp_input_66.c:
     *        2535-2548) for a no-SACK Reno connection at exactly high_seq -
     *        reopening there lets the next dup-ACK start a false fast
     *        retransmit (RFC 2582). The port's CA_Loss exit (tcp_fsm.cpp:
     *        3766-3780) closed the episode unconditionally, so this pins it.
     */
    void TestNonSackLossHoldsAtHighSeq() {
        FsmHarness h;
        h.conn.SetSackOk(false);   // kernel tcp_is_reno(tp)
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 4; ++i) {
            h.Send(kMss);
        }
        const UInt32 end = h.conn.SndNxt();
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);   // RTO -> CA_Loss, high_seq = snd_nxt
        g_recCalls = 0;
        g_recCaState = 0xFF;
        h.now += 20000;
        h.Deliver(end);                    // ACK exactly at high_seq
        CHECK(1 <= g_recCalls);
        CHECK(4u == g_recCaState);         // held CA_Loss (red: 0 before the fix)
        // The ACK above high_seq (new data sent after the held ACK) ends it.
        h.Send(kMss);
        g_recCalls = 0;
        g_recCaState = 0xFF;
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        CHECK(1 <= g_recCalls);
        CHECK(0u == g_recCaState);
    }

    /**
     * @brief Kernel tcp_enter_loss (tcp_input_66.c:2165-2173) re-cuts
     *        ssthresh only when state <= TCP_CA_Disorder, snd_una >=
     *        high_seq, or (state == Loss && !retransmits). An RTO that
     *        fires while the connection is already in CA_Recovery must NOT
     *        cut again - a reduction was already made in this window. The
     *        port's guard was `(4 != ca_state)` (any state but Loss), which
     *        re-cut during CWR/Recovery (audit D20).
     */
    void TestRtoInRecoveryDoesNotRecut() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 4; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);   // dup-ACKs -> CA_Recovery
        }
        CHECK(h.conn.FastRecovery());
        const UInt32 ssth_rec = h.conn.Ssthresh();
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);   // RTO during Recovery
        CHECK(ssth_rec == h.conn.Ssthresh());   // red: halved before the fix
    }

    /**
     * @brief A no-SACK partial ACK must retransmit the next hole.
     *
     * Kernel tcp_identify_packet_loss (tcp_input_66.c:2941-2956) dispatches
     * the NewReno arm for a non-SACK connection:
     *
     *     if (unlikely(tcp_is_reno(tp)))
     *         tcp_newreno_mark_lost(sk, *ack_flag & FLAG_SND_UNA_ADVANCED);
     *
     * and tcp_newreno_mark_lost (tcp_recovery_66.c:217-236) marks the
     * retransmit-queue head LOST when
     *
     *     (state < TCP_CA_Recovery && sacked_out >= reordering) ||
     *     (state == TCP_CA_Recovery && snd_una_advanced)
     *
     * - i.e. a cumulative ACK that advances snd_una during recovery marks
     * the NEXT hole lost. tcp_xmit_recovery then retransmits it. That is the
     * whole point of NewReno (RFC 6582 s3.2): each partial ACK repairs one
     * hole, so recovery advances one segment per round trip instead of
     * waiting for the RTO.
     *
     * The port dropped the retransmit for the no-SACK partial-ACK path (it
     * only deflated cwnd), so recovery stalled until the RTO fired.
     */
    void TestNonSackPartialAckRetransmitsNextHole() {
        FsmHarness h;
        h.conn.SetSackOk(false);   // kernel tcp_is_reno(tp)
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 6; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        const UInt32 end = h.conn.SndNxt();
        // Enter recovery with 3 raw dup-ACKs (no SACK blocks).
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);
        }
        CHECK(h.conn.FastRecovery());
        const UInt32 retx_entry = h.conn.RetransmitCount();
        CHECK(1 == retx_entry);   // the entry retransmitted the head
        // A partial ACK: advances snd_una by exactly one MSS, still below
        // high_seq, so the episode stays open.
        h.now += 20000;
        h.Deliver(una + kMss);
        // Kernel: tcp_newreno_mark_lost marks the next hole and
        // tcp_xmit_recovery retransmits it.
        CHECK(retx_entry + 1 == h.conn.RetransmitCount());
        CHECK(h.conn.FastRecovery());
        CHECK(xtcp::core::SeqLt(h.conn.SndUna(), end));
    }

    /**
     * @brief A Reno-path probe recording undo_cwnd calls and COMPLETE_CWR
     *        events (kernel tcp_undo_cwnd_reduction / tcp_ca_event).
     */
    UInt32 g_probeUndoCalls = 0;
    UInt32 g_probeCompleteCwr = 0;
    [[maybe_unused]] Byte g_probeCaState = 0xFF;

    UInt32 ProbeUndoCwnd(XtcpConnCc* sk) noexcept {
        ++g_probeUndoCalls;
        return sk->snd_cwnd;
    }
    void ProbeCwndEvent(XtcpConnCc*, xtcp::cc::CaEvent ev) noexcept {
        if (xtcp::cc::kCaEventCompleteCwr == ev) {
            ++g_probeCompleteCwr;
        }
    }
    void ProbeSetState(XtcpConnCc*, Byte) noexcept {}

    void EnsureUndoProbeCc() {
        static bool registered = false;
        if (registered) {
            return;
        }
        XtcpCongestionOps ops;
        ops.name = "kcc_test_undo_probe";
        ops.undo_cwnd = ProbeUndoCwnd;
        ops.cwnd_event = ProbeCwndEvent;
        ops.set_state = ProbeSetState;
        // NO cong_control and NO ssthresh: the classic Reno path, so
        // EndCwndReduction's guards are actually exercised.
        CHECK(xtcp::cc::RegisterCongestionControl(ops));
        registered = true;
    }

    /**
     * @brief Batch 4 (D08) T4-1: the PRR arithmetic must stay in PACKETS.
     *
     * Kernel tcp_cwnd_reduction (tcp_input.c:2643-2667) is entirely in packets:
     * `tp->prr_delivered += newly_acked_sacked` where newly_acked_sacked comes
     * from tcp_tso_acked, and sndcnt/delta are packet counts. The port used to
     * add `acked` (BYTES) to a packet-domain ssthresh, so a 2*MSS partial ACK
     * turned a 3-segment window into 2923 segments (probe P6).
     */
    void TestPrrStaysInPackets() {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(4u << 20);
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 6; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true,
                          una + 2 * kMss, una + 6 * kMss);
        }
        CHECK(conn.FastRecovery());
        const UInt32 ssth = conn.Ssthresh();
        // Partial ACK advancing 2*MSS with a SACK block leaving a gap: the PRR
        // value survives (gaps_remain stays true, so no exit/undo overwrite).
        now += 20000;
        DeliverRawAck(conn, now, una + 2 * kMss, xtcp::core::kFlagAck, true,
                      una + 3 * kMss, una + 6 * kMss);
        std::fprintf(stderr, "[T4-1] ssth=%u partial_ack_cwnd=%u\n", ssth, conn.Cwnd());
        // RED on HEAD: 2923 = ssthresh(3) + 2920 acked BYTES.
        CHECK(conn.Cwnd() <= ssth + 8u);
        // Coarse packet-domain sanity bound (the 2^31 sentinel shape is caught
        // by this one; the exact red case above is the byte-domain 2923).
        CHECK(conn.Cwnd() < 100000u);
    }

    /**
     * @brief Batch 4 review (D): a RETRANSMISSION must spend PRR credit too.
     *
     * Kernel increments tp->prr_out in TWO places:
     *   tcp_output_66.c:2787-2789  tcp_write_xmit        -> prr_out += sent_pkts
     *   tcp_output_66.c:3461-3462  tcp_xmit_retransmit_queue
     *                                                     -> prr_out += tcp_skb_pcount(skb)
     * The port only mirrored the first (SendData / FlushPendingSend). In a SACK
     * recovery whose progress is driven by RETRANSMISSIONS, prr_out_ stayed ~0
     * while prr_delivered_ grew, so `cwnd = ssthresh + delivered - out` climbed
     * monotonically and PRR stopped pacing the recovery (probe a4rev60:
     * 6 -> 5 -> 6 -> 7 -> 8 -> 9 against ssthresh 5).
     */
    void TestPrrChargesRetransmissions() {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(8u << 20);
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 12; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        const UInt32 end = conn.SndNxt();
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true,
                          una + kMss, una + 2 * kMss);
        }
        CHECK(conn.FastRecovery());
        const UInt32 ssth = conn.Ssthresh();
        const UInt32 cut = conn.Cwnd();
        std::fprintf(stderr, "[T4-D] entry ssth=%u cut=%u\n", ssth, cut);
        // Six partial ACKs, each advancing 1 MSS with a SACK block leaving a
        // gap: gaps_remain stays true and each ACK drives one retransmission.
        for (UInt32 k = 1; k <= 6; ++k) {
            now += 20000;
            const size_t before = tx.size();
            DeliverRawAck(conn, now, una + k * kMss, xtcp::core::kFlagAck, true,
                          una + (k + 1) * kMss, end);
            std::fprintf(stderr, "[T4-D] partial#%u retx=%zu cwnd=%u ssth=%u\n",
                         k, tx.size() - before, conn.Cwnd(), conn.Ssthresh());
        }
        // RED without the retransmission accounting: 9 vs ssthresh+2 = 7.
        // With it, every ACK's 1 delivered packet is offset by its 1
        // retransmitted packet, so the window stays at ssthresh.
        CHECK(conn.Cwnd() <= conn.Ssthresh() + 2u);
    }

    /**
     * @brief D01/review-defect 2: a SACK-confirmed recovery that is NOT undone
     *        must end with cwnd = ssthresh.
     *
     * Kernel tcp_fastretrans_alert part D (tcp_input.c:3012-3018):
     * tcp_try_undo_recovery returns false (a SACK entry has no undo), then
     * tcp_end_cwnd_reduction runs; its guard (tcp_input.c:2676-2680) is
     * `snd_ssthresh < TCP_INFINITE_SSTHRESH && (state == CWR || undo_marker)`.
     * For a SACK entry `undo_marker` is 0, so the guard must be evaluated on
     * "the episode was not undone" - the port reused undo_marker_ for that,
     * and the SACK entry sets it false, so the collapse was skipped
     * (review_batch1 defect 2: cut=11 ssth=5, exit cwnd stayed 11).
     */
    void TestRecoveryExitCollapsesToSsthresh() {
        EnsureUndoProbeCc();
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(4u << 20);
        CHECK(conn.SetCongestionControl("kcc_test_undo_probe"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 10; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true,
                          una + kMss, una + 2 * kMss);
        }
        CHECK(conn.FastRecovery());
        const UInt32 cwnd_cut = conn.Cwnd();
        const UInt32 ssth_cut = conn.Ssthresh();
        CHECK(cwnd_cut > ssth_cut);            // the entry cut, so they differ
        now += 20000;
        DeliverRawAck(conn, now, conn.SndNxt());
        CHECK(!conn.FastRecovery());
        std::fprintf(stderr, "[d01-collapse] cut=%u ssth=%u exit=%u\n",
                     cwnd_cut, ssth_cut, conn.Cwnd());
        CHECK(conn.Cwnd() == ssth_cut);        // red: 11 (stayed at cut)
    }

    /**
     * @brief Review-defect 3: a held NON-SACK recovery must undo FIRST.
     *
     * Kernel tcp_try_undo_recovery (tcp_input.c:2551-2574) runs
     * tcp_may_undo -> tcp_undo_cwnd_reduction (restores prior_cwnd) and only
     * THEN tcp_is_non_sack_preventing_reopen (2572-2573) returns true, which
     * keeps the state in Recovery and skips tcp_end_cwnd_reduction - so no
     * CA_EVENT_COMPLETE_CWR on this ACK. The port cleared the marker instead
     * of undoing (review_batch1 defect 3: undo_calls=0).
     */
    void TestNonSackHoldUndoesFirst() {
        EnsureUndoProbeCc();
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(false);
        conn.SetSndBuf(4u << 20);
        CHECK(conn.SetCongestionControl("kcc_test_undo_probe"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 4; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        const UInt32 end = conn.SndNxt();
        const UInt32 cwnd_pre = conn.Cwnd();
        // Zero-window dup-ACKs: the no-SACK entry still arms undo_marker_, but
        // RetransmitEarliestMissing skips the transmit (RFC 1122 s4.2.2.17,
        // `0 == snd_wnd_`), so NO retransmission is put on the wire and
        // undo_retrans stays -1. That is the kernel's "Happy end! We did not
        // retransmit anything" case (tcp_input.c:2558-2560) where tcp_may_undo
        // allows the undo. With a real retransmission in flight the kernel's
        // counter (tcp_output_66.c:3390-3392) makes tcp_may_undo refuse without
        // TSopt evidence (tcp_input.c:2530-2533) - covered by T2-4.
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, false, 0, 0, 0);
        }
        CHECK(conn.FastRecovery());
        const UInt32 ssth_cut = conn.Ssthresh();
        CHECK(cwnd_pre > ssth_cut);
        g_probeUndoCalls = 0;
        g_probeCompleteCwr = 0;
        // ACK exactly at high_seq: held, but the undo MUST have run first.
        now += 20000;
        DeliverRawAck(conn, now, end);
        CHECK(1 <= g_probeUndoCalls);          // red: 0
        CHECK(conn.FastRecovery());            // still held
        CHECK(0 == g_probeCompleteCwr);        // no episode end on this ACK
        CHECK(conn.Cwnd() > ssth_cut);         // window restored (not collapsed)
        // ACK above high_seq: now the episode ends - but because the window
        // was already undone, tcp_end_cwnd_reduction must NOT collapse it.
        {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        now += 20000;
        DeliverRawAck(conn, now, conn.SndNxt());
        CHECK(!conn.FastRecovery());
        CHECK(1 == g_probeCompleteCwr);        // exactly one episode end
        CHECK(conn.Cwnd() > ssth_cut);         // red: collapsed to ssthresh
    }

    /**
     * @brief Review-defect 1: a CA_Loss exit must NOT call
     *        tcp_end_cwnd_reduction.
     *
     * Kernel tcp_process_loss ends with `tcp_try_undo_recovery(sk); return;`
     * (tcp_input.c:2881-2885) - no tcp_end_cwnd_reduction, hence no
     * CA_EVENT_COMPLETE_CWR. The port's shared `else` branch fired the event
     * for Loss too (review_batch1 item 1: complete_cwr=1, kernel 0).
     */
    void TestLossExitHasNoCompleteCwr() {
        EnsureUndoProbeCc();
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(4u << 20);
        CHECK(conn.SetCongestionControl("kcc_test_undo_probe"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 4; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 end = conn.SndNxt();
        // RTO: enters CA_Loss (kernel tcp_enter_loss), no fast recovery.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        CHECK(!conn.FastRecovery());
        g_probeCompleteCwr = 0;
        now += 20000;
        DeliverRawAck(conn, now, end);
        std::fprintf(stderr, "[d01-loss-exit] complete_cwr=%u\n", g_probeCompleteCwr);
        CHECK(0 == g_probeCompleteCwr);        // red: 1
    }

    /**
     * @brief Review-defect 7: a migration checkpoint must reset the congestion
     *        view of the TARGET connection.
     *
     * The checkpoint carries no congestion state, so every episode/undo field
     * must be reset to its "no episode" value instead of leaking the target
     * connection's previous values. Batch 5 (D10) owns the full reset; this
     * pins the batch-1 fields.
     */
    void TestApplyCheckpointResetsCongestionView() {
        std::vector<xtcp::buf::BufRef> tx_a;
        xtcp::core::TcpConn src(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx_a](xtcp::buf::BufRef&& p) { tx_a.push_back(std::move(p)); });
        src.SetPeerMss(kMss);
        src.SetSackOk(false);
        src.SetSndBuf(4u << 20);
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 4; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(src.SendData(buf.data(), kMss, now));
        }
        now += 3000000;
        src.OnRetransmitTimer(now);          // rto_pending_ = true, undo_retrans_
        CHECK(src.RtoPending());
        const xtcp::core::TcpConn::ConnCheckpoint ck = src.MakeCheckpoint();
        // The target has its own stale congestion view.
        std::vector<xtcp::buf::BufRef> tx_b;
        xtcp::core::TcpConn dst(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 500, 900,
            [&tx_b](xtcp::buf::BufRef&& p) { tx_b.push_back(std::move(p)); });
        dst.SetPeerMss(kMss);
        dst.SetSndBuf(4u << 20);
        dst.ApplyCheckpoint(ck);
        CHECK(-1 == dst.UndoRetrans());      // red: leaked a positive value
        CHECK(!dst.RtoPending());            // red: leaked true
        CHECK(0u == dst.HighSeq());          // red: leaked the source's high_seq
    }

    /**
     * @brief Batch 5 (D10) T5-1: ApplyCheckpoint must reset the WHOLE
     *        congestion view to "fresh connection, Open state".
     *
     * The checkpoint carries no congestion state (no cwnd/ssthresh/ca_state/
     * prr_*). Batch 1 reset only the episode/undo subset, so the TARGET's
     * already-cut window survived the restore: a migrated flow kept sending at
     * the destination's Loss/Recovery window and never restarted from
     * initcwnd (audit D10).
     *
     * Red baseline: cwnd stays at the destination's cut value (2) and
     * ssthresh at its cut value, instead of 10 / 0x7FFFFFFF.
     */
    void TestApplyCheckpointFullReset() {
        // Source: an ordinary checkpoint (one segment in flight).
        FsmHarness src;
        src.Send(kMss);
        const xtcp::core::TcpConn::ConnCheckpoint ck = src.conn.MakeCheckpoint();
        CHECK(1 == ck.retrans_queue.size());

        // Destination: its OWN stale recovery episode (Reno entry, no SACK).
        FsmHarness dst;
        dst.conn.SetSackOk(false);
        dst.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 4; ++i) {
            dst.Send(kMss);
        }
        const UInt32 una = dst.conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            dst.now += 1000;
            dst.Deliver(una);
        }
        CHECK(dst.conn.FastRecovery());
        CHECK(dst.conn.Cwnd() < 10);
        const UInt32 cwnd_stale = dst.conn.Cwnd();
        const UInt32 ssth_stale = dst.conn.Ssthresh();

        dst.conn.ApplyCheckpoint(ck);
        std::fprintf(stderr,
                     "[T5-1] stale cwnd=%u ssth=%u -> after restore cwnd=%u ssth=%u fr=%d\n",
                     cwnd_stale, ssth_stale, dst.conn.Cwnd(), dst.conn.Ssthresh(),
                     dst.conn.FastRecovery() ? 1 : 0);
        CHECK(10u == dst.conn.Cwnd());             // red: stale cut value
        CHECK(0x7FFFFFFFu == dst.conn.Ssthresh()); // red: stale cut value
        CHECK(!dst.conn.FastRecovery());
        CHECK(0u == dst.conn.HighSeq());
    }

    /**
     * @brief Batch 5 (D11) T5-2: RACK must not re-enter Recovery while an RTO
     *        episode owns the loss verdict (CA_Loss / rto_pending_).
     *
     * Kernel tcp_process_loss (tcp_input.c:2845-2896) owns CA_Loss; entering
     * tcp_enter_recovery there would overwrite prior_cwnd_/prior_ssthresh_
     * with the ALREADY-CUT window and reset high_seq_ (audit D11).
     *
     * Red baseline: the RACK verdict cuts the window a second time
     * (cwnd 1 -> 2, ssthresh unchanged) and sets fast_recovery_.
     */
    /**
     * @brief Kernel tcp_enter_loss must not re-cut ssthresh for a repeated
     *        timeout inside the SAME loss window.
     *
     * tcp_input_66.c:2165-2173 guards the reduction with
     *   state <= Disorder || !after(high_seq, snd_una) ||
     *   (state == Loss && !icsk_retransmits)
     * so a second RTO while snd_una is still below high_seq and a
     * retransmission is already outstanding keeps the FIRST cut - and the
     * first prior_ssthresh/prior_cwnd snapshot, which the spurious-RTO undo
     * later restores. cwnd = packets_in_flight + 1 still applies.
     *
     * Red baseline: ssthresh goes 5 -> 2 -> 2 across three back-to-back RTOs
     * and prior_cwnd_ is overwritten with an already-cut window.
     */
    void TestRepeatedRtoKeepsFirstCut() {
        FsmHarness h;
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 10; ++i) {
            h.Send(kMss);
        }
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        const UInt32 ssth_first = h.conn.Ssthresh();
        const UInt32 cwnd_first = h.conn.Cwnd();
        CHECK(5u == ssth_first);   // max(cwnd 10 >> 1, 2)
        CHECK(1u == cwnd_first);   // pipe empty (head LOST) + 1

        // Two more timeouts inside the same window (snd_una < high_seq).
        for (UInt32 r = 0; r < 2; ++r) {
            h.now += 3000000;
            h.conn.OnRetransmitTimer(h.now);
            std::fprintf(stderr, "[repeated-rto] r=%u cwnd=%u ssth=%u\n",
                         r + 1, h.conn.Cwnd(), h.conn.Ssthresh());
            CHECK(ssth_first == h.conn.Ssthresh());   // red: halved to 2
            CHECK(1u == h.conn.Cwnd());
        }

        // A cumulative ACK that advances snd_una opens a NEW window, so the
        // next timeout cuts again (kernel tcp_clear_retrans zeroes
        // icsk_retransmits).
        h.now += 20000;
        h.Deliver(h.conn.SndUna() + kMss);
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        std::fprintf(stderr, "[repeated-rto] new window ssth=%u\n", h.conn.Ssthresh());
        CHECK(ssth_first != h.conn.Ssthresh());       // a fresh cut happened
        CHECK(2u == h.conn.Ssthresh());               // max(cwnd 2 >> 1, 2)
    }

    void TestRackDoesNotReenterLoss() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 4; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        // RTO: CA_Loss, rto_pending_ = true, cwnd cut to 1 (Reno path).
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        CHECK(h.conn.RtoPending());
        const UInt32 cwnd_rto = h.conn.Cwnd();
        const UInt32 ssth_rto = h.conn.Ssthresh();
        CHECK(1u == cwnd_rto);
        // Kernel tcp_reno_ssthresh is max(cwnd >> 1, 2) (tcp_cong_66.c) - it
        // follows the WINDOW, not the post-loss pipe. The harness CC has no
        // ssthresh hook, so the Reno branch applies: cwnd was 10 before the
        // cut, giving 5.
        CHECK(5u == ssth_rto);

        // Dup-ACK whose SACK block delivers segment 3: RACK anchors on it and
        // segment 2 (sent before the RTO) is overdue -> a loss verdict.
        h.now += 20000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true,
                  una + 2 * kMss, una + 3 * kMss);
        std::fprintf(stderr,
                     "[T5-2] after RTO cwnd=%u ssth=%u -> after RACK cwnd=%u ssth=%u fr=%d\n",
                     cwnd_rto, ssth_rto, h.conn.Cwnd(), h.conn.Ssthresh(),
                     h.conn.FastRecovery() ? 1 : 0);
        CHECK(!h.conn.FastRecovery());       // red: RACK entered Recovery
        CHECK(cwnd_rto == h.conn.Cwnd());    // red: cut again to ssthresh
        CHECK(ssth_rto == h.conn.Ssthresh());
    }

    /**
     * @brief Batch 5 (D11) T5-2b: RACK must not recut the window in CA_CWR.
     *
     * Kernel tcp_enter_recovery guards its reduction with
     * `if (!tcp_in_cwnd_reduction(sk))` (tcp_input_66.c:2834-2839) and
     * tcp_in_cwnd_reduction covers BOTH CWR and Recovery (tcp_66.h:1245-1249).
     * During CWR the reduction snapshot already exists, so a RACK verdict must
     * only move the state - it must NOT run tcp_init_cwnd_reduction a second
     * time and halve ssthresh again (audit B, batch 5 review).
     *
     * Red baseline (gate only excluded CA_Loss): after an ECE the flow sits in
     * CWR with ssthresh already cut; a SACK dup-ACK makes RACK fire, which
     * recuts ssthresh and sets fast_recovery_.
     */
    void TestRackDoesNotRecutInCwr() {
        // A real handshake is required: ecn_active_ is only assigned on the
        // handshake paths (tcp_fsm.cpp:5416 / :5582), never by a direct
        // kEstablished construction.
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kSynSent, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSndBuf(8u << 20);
        conn.SetEcnRequested(true);   // our SYN offers ECE+CWR
        xtcp::core::TimePoint now = 1000;
        conn.SendSyn();
        const UInt32 our_syn_ts = TsvalOf(tx.back());
        // Peer's SYN+ACK with ECE -> ecn_active_ = true.
        const std::vector<Byte> synack = BuildSegTs(
            443, 40000, 500, 101,
            static_cast<UInt16>(xtcp::core::kFlagSyn | xtcp::core::kFlagAck |
                                xtcp::core::kFlagEce),
            65535, 777, our_syn_ts, false, 0, 0, true);
        conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), now);
        CHECK(xtcp::core::TcpState::kEstablished == conn.State());
        CHECK(conn.EcnActive());

        for (UInt32 i = 0; i < 8; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        // An ECE ACK enters CWR (kernel tcp_enter_cwr) and cuts ssthresh.
        now += 1000;
        const std::vector<Byte> ece = BuildSegTs(
            40000, 443, 201, una,
            static_cast<UInt16>(xtcp::core::kFlagAck | xtcp::core::kFlagEce),
            65535, 778, our_syn_ts);
        conn.OnSegment(ece.data(), static_cast<UInt32>(ece.size()), now);
        const UInt32 ssth_cwr = conn.Ssthresh();
        CHECK(0x7FFFFFFFu != ssth_cwr);      // the CWR cut was recorded
        CHECK(!conn.FastRecovery());

        // A later SACK dup-ACK: segment 1 is overdue, so RACK has a verdict.
        now += 500000;
        const std::vector<Byte> sack = BuildSegTs(
            40000, 443, 201, una, xtcp::core::kFlagAck, 65535, 779, our_syn_ts,
            true, una + 2 * kMss, una + 3 * kMss);
        conn.OnSegment(sack.data(), static_cast<UInt32>(sack.size()), now);
        std::fprintf(stderr, "[T5-2b] cwr ssth=%u -> after RACK ssth=%u fr=%d\n",
                     ssth_cwr, conn.Ssthresh(), conn.FastRecovery() ? 1 : 0);
        CHECK(!conn.FastRecovery());       // red: RACK entered Recovery
        CHECK(ssth_cwr == conn.Ssthresh());  // red: ssthresh halved again
    }

    /**
     * @brief RACK must mark EVERY overdue segment lost, not just the first.
     *
     * Kernel tcp_rack_detect_loss (tcp_recovery_66.c:53-88) walks the whole
     * tsorted_sent_queue and marks each overdue skb, WITHOUT breaking out of
     * the loop:
     *
     *     list_for_each_entry_safe(skb, n, &tp->tsorted_sent_queue, ...) {
     *         ...
     *         if (!tcp_skb_sent_after(tp->rack.mstamp, ...))
     *             break;
     *         remaining = tcp_rack_skb_timeout(tp, skb, reo_wnd);
     *         if (remaining <= 0) {
     *             tcp_mark_skb_lost(sk, skb);
     *             list_del_init(&skb->tcp_tsorted_anchor);
     *         } else {
     *             *reo_timeout = max_t(u32, *reo_timeout, remaining);
     *         }
     *     }
     *
     * The `break` there is the ordering cutoff (segments sent AFTER the RACK
     * anchor are not judged); a segment that IS overdue does not stop the
     * scan. Stopping at the first verdict leaves the rest of the overdue
     * flight inside packets_out, so tcp_packets_in_flight() over-reports and
     * the recovery entry computes its window from an inflated pipe.
     */
    void TestRackMarksAllOverdueLost() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 5; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        // Let every segment age well past the reorder window.
        h.now += 200000;
        // SACK only the LAST segment: the RACK anchor lands on it, and the
        // four before it are all overdue.
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true,
                  una + 4 * kMss, una + 5 * kMss);
        std::fprintf(stderr,
                     "[rack-all] lost_out=%u retrans_out=%u fr=%d\n",
                     h.conn.LostOutPkts(), h.conn.RetransOutPkts(),
                     h.conn.FastRecovery() ? 1 : 0);
        // Four segments are overdue: the kernel marks all four lost.
        CHECK(4 == h.conn.LostOutPkts());
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());
    }

    /**
     * @brief Batch 5 (D11) T5-3: the RTO snapshot survives a RACK verdict.
     *
     * T5-2 blocks the RACK entry outright; this test pins the OUTCOME the
     * first-save gate protects: the spurious-RTO undo must restore the window
     * the RTO saved, never the value RACK would have captured after the cut.
     * (The first-save gate at the RACK capture is the symmetric guard of the
     * RTO one at tcp_fsm.cpp:1764.)
     *
     * Red baseline: RACK re-entry clears rto_pending_/retrans_stamp_ts_, so
     * the Eifel adjudication never runs and the window stays cut.
     */
    void TestRackKeepsRtoSnapshot() {
        EnsureRecorderCc();   // owns cwnd growth so only the undo changes it
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kSynSent, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSndBuf(4u << 20);
        conn.SetSackOk(true);
        xtcp::core::TimePoint now = 1000;
        conn.SendSyn();
        const UInt32 our_syn_ts = TsvalOf(tx.back());
        const std::vector<Byte> synack = BuildSegTs(
            443, 40000, 500, 101,
            static_cast<UInt16>(xtcp::core::kFlagSyn | xtcp::core::kFlagAck), 65535,
            777, our_syn_ts, false, 0, 0, true);
        conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), now);
        CHECK(xtcp::core::TcpState::kEstablished == conn.State());
        CHECK(conn.SetCongestionControl("kcc_test_rec"));

        // Grow the window (Reno) so the RTO's pre-cut value is distinctive.
        for (UInt32 r = 0; r < 8; ++r) {
            const UInt32 cwnd = conn.Cwnd();
            for (UInt32 i = 0; i < cwnd; ++i) {
                std::vector<Byte> buf(kMss, 0x41);
                CHECK(conn.SendData(buf.data(), kMss, now));
            }
            now += 20000;
            const std::vector<Byte> a = BuildSegTs(
                40000, 443, 201, conn.SndNxt(), xtcp::core::kFlagAck, 65535,
                0, 0);
            conn.OnSegment(a.data(), static_cast<UInt32>(a.size()), now);
        }
        const UInt32 cwnd_pre = conn.Cwnd();
        CHECK(8 < cwnd_pre);

        for (UInt32 i = 0; i < 3; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        // RTO: prior_cwnd_ = cwnd_pre, cwnd cut to 1.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        CHECK(conn.RtoPending());
        CHECK(1u == conn.Cwnd());

        // RACK verdict attempt: deliver segment 3, leave segment 2 overdue.
        now += 20000;
        const std::vector<Byte> dup = BuildSegTs(
            40000, 443, 201, una, xtcp::core::kFlagAck, 65535, 0, 0, true,
            una + 2 * kMss, una + 3 * kMss);
        conn.OnSegment(dup.data(), static_cast<UInt32>(dup.size()), now);

        // ACK covering the whole flight (the retransmitted range included),
        // echoing a TSval OLDER than the RTO's -> spurious RTO -> Eifel undo
        // restores prior_cwnd_. The queue empties here, so no RACK verdict can
        // fire on this ACK and mask the restored window.
        now += 20000;
        const std::vector<Byte> a = BuildSegTs(
            40000, 443, 201, conn.SndNxt(), xtcp::core::kFlagAck, 65535, 888, 1);
        conn.OnSegment(a.data(), static_cast<UInt32>(a.size()), now);
        std::fprintf(stderr, "[T5-3] pre=%u rto_cwnd=1 -> after undo cwnd=%u fr=%d\n",
                     cwnd_pre, conn.Cwnd(), conn.FastRecovery() ? 1 : 0);
        CHECK(!conn.RtoPending());
        CHECK(cwnd_pre == conn.Cwnd());   // red: snapshot clobbered by RACK
        CHECK(!conn.FastRecovery());
    }

    /**
     * @brief Batch 5 addendum (A): ApplyCheckpoint's cc_ops_->init must fully
     *        reset the PLUGIN's private recovery state.
     *
     * KccInit (cc_kcc.cpp:770-789) only resets mode/gains/p_est/idle/drain/
     * next_rtt/rand/min_rtt/snd_cwnd. The rest of KccState (prev_ca_state,
     * packet_conservation, full_bw, total_delivered, max_bw, cycle_idx, ...)
     * is left untouched, and ApplyCheckpoint does not drop ca_priv, so init
     * REUSES the same KccState: the destination shard's old recovery epoch
     * survives the migration (audit A).
     *
     * The connection runs the real KCC plugin through a thin forwarding wrapper
     * so the test can capture the XtcpConnCc* and read the private state with
     * the read-only KccGetSnapshot probe.
     */
    const xtcp::cc::XtcpCongestionOps* g_b5KccInner = NULLPTR;
    XtcpConnCc* g_b5KccSk = NULLPTR;

    void B5KccWrapInit(XtcpConnCc* sk) noexcept {
        g_b5KccSk = sk;
        if (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->init) {
            g_b5KccInner->init(sk);
        }
    }
    void B5KccWrapRelease(XtcpConnCc* sk) noexcept {
        if (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->release) {
            g_b5KccInner->release(sk);
        }
    }
    UInt32 B5KccWrapSsthresh(XtcpConnCc* sk) noexcept {
        return (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->ssthresh)
            ? g_b5KccInner->ssthresh(sk) : sk->snd_ssthresh;
    }
    void B5KccWrapSetState(XtcpConnCc* sk, Byte s) noexcept {
        if (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->set_state) {
            g_b5KccInner->set_state(sk, s);
        }
    }
    void B5KccWrapEvent(XtcpConnCc* sk, xtcp::cc::CaEvent ev) noexcept {
        if (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->cwnd_event) {
            g_b5KccInner->cwnd_event(sk, ev);
        }
    }
    UInt32 B5KccWrapUndo(XtcpConnCc* sk) noexcept {
        return (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->undo_cwnd)
            ? g_b5KccInner->undo_cwnd(sk) : sk->snd_cwnd;
    }
    void B5KccWrapControl(XtcpConnCc* sk, const RateSample* rs) noexcept {
        if (NULLPTR != g_b5KccInner && NULLPTR != g_b5KccInner->cong_control) {
            g_b5KccInner->cong_control(sk, rs);
        }
    }

    void EnsureB5KccWrapper() {
        static bool registered = false;
        xtcp::cc::RegisterKcc();
        g_b5KccInner = xtcp::cc::FindCongestionControl("kcc");
        CHECK(NULLPTR != g_b5KccInner);
        if (registered) {
            return;
        }
        XtcpCongestionOps ops;
        ops.name = "b5_kcc_wrap";
        ops.init = B5KccWrapInit;
        ops.release = B5KccWrapRelease;
        ops.ssthresh = B5KccWrapSsthresh;
        ops.set_state = B5KccWrapSetState;
        ops.cwnd_event = B5KccWrapEvent;
        ops.undo_cwnd = B5KccWrapUndo;
        ops.cong_control = B5KccWrapControl;
        CHECK(xtcp::cc::RegisterCongestionControl(ops));
        registered = true;
    }

    void TestMigrationResetsKccRecoveryState() {
        EnsureB5KccWrapper();
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSndBuf(4u << 20);
        conn.SetSackOk(true);
        CHECK(conn.SetCongestionControl("b5_kcc_wrap"));
        CHECK(NULLPTR != g_b5KccSk);
        xtcp::core::TimePoint now = 1000;
        // Warm-up: ACK-clocked rounds so KCC's estimator accumulates
        // total_delivered / max_bw / full_bw.
        for (UInt32 r = 0; r < 8; ++r) {
            const UInt32 cwnd = conn.Cwnd();
            for (UInt32 i = 0; i < cwnd; ++i) {
                std::vector<Byte> buf(kMss, 0x41);
                CHECK(conn.SendData(buf.data(), kMss, now));
            }
            now += 20000;
            DeliverRawAck(conn, now, conn.SndNxt());
        }
        // Enter Recovery, then one advancing ACK: KCC latches
        // packet_conservation=1 and prev_ca_state=3.
        for (UInt32 i = 0; i < 6; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        for (UInt32 i = 0; i < 3; ++i) {
            now += 1000;
            DeliverRawAck(conn, now, una);
        }
        CHECK(conn.FastRecovery());
        now += 1000;
        DeliverRawAck(conn, now, una + kMss);

        KccSnapshot before;
        CHECK(xtcp::cc::KccGetSnapshot(g_b5KccSk, &before));
        std::fprintf(stderr,
                     "[A] pre-migration kcc: prev_ca=%u cons=%u full_bw=%llu "
                     "total_delivered=%llu max_bw=%llu\n",
                     before.prev_ca_state, before.packet_conservation,
                     static_cast<unsigned long long>(before.full_bw),
                     static_cast<unsigned long long>(before.total_delivered),
                     static_cast<unsigned long long>(before.max_bw));
        CHECK(1u == before.packet_conservation);   // the epoch really is live
        CHECK(0u != before.prev_ca_state);

        // Ordinary checkpoint from a plain source connection.
        FsmHarness src;
        src.Send(kMss);
        const xtcp::core::TcpConn::ConnCheckpoint ck = src.conn.MakeCheckpoint();
        conn.ApplyCheckpoint(ck);

        KccSnapshot after;
        CHECK(xtcp::cc::KccGetSnapshot(g_b5KccSk, &after));
        std::fprintf(stderr,
                     "[A] post-migration kcc: prev_ca=%u cons=%u full_bw=%llu "
                     "total_delivered=%llu max_bw=%llu\n",
                     after.prev_ca_state, after.packet_conservation,
                     static_cast<unsigned long long>(after.full_bw),
                     static_cast<unsigned long long>(after.total_delivered),
                     static_cast<unsigned long long>(after.max_bw));
        CHECK(0u == after.packet_conservation);    // red: stale 1
        CHECK(0u == after.prev_ca_state);          // red: stale 3
        CHECK(0ull == after.full_bw);              // red: stale estimate
        CHECK(0ull == after.total_delivered);      // red: stale epoch
        CHECK(0ull == after.max_bw);               // red: stale estimate
    }

    /**
     * @brief Migration must carry TCPCB_RETRANS with the segment.
     *
     * Kernel tcp_clean_rtx_queue decrements retrans_out only for an skb still
     * tagged TCPCB_SACKED_RETRANS (tcp_input_66.c:3300-3310), and the
     * FLAG_RETRANS_DATA_ACKED bit feeds the delayed-ACK heuristic. A
     * checkpoint that drops is_retrans makes a migrated retransmit look like a
     * first transmission: popping it leaves retrans_out_pkts_ inflated forever
     * (the pipe never empties) and suppresses batch_retrans_.
     *
     * Red baseline: after the migration and a full cumulative ACK,
     * RetransOutPkts() stays 1 instead of returning to 0.
     */
    void TestMigrationKeepsRetransTag() {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn src(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        src.SetPeerMss(kMss);
        src.SetSndBuf(4u << 20);
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 4; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(src.SendData(buf.data(), kMss, now));
        }
        // RTO retransmits the head, tagging it TCPCB_RETRANS.
        now += 3000000;
        src.OnRetransmitTimer(now);
        CHECK(1u == src.RetransOutPkts());
        const xtcp::core::TcpConn::ConnCheckpoint ck = src.MakeCheckpoint();
        CHECK(4 == ck.retrans_queue.size());
        // The head was the RTO retransmit: it carries the TCPCB_RETRANS tag.
        CHECK(1u == ck.retrans_queue.front().is_retrans);

        std::vector<xtcp::buf::BufRef> tx2;
        xtcp::core::TcpConn dst(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 500, 900,
            [&tx2](xtcp::buf::BufRef&& p) { tx2.push_back(std::move(p)); });
        dst.SetPeerMss(kMss);
        dst.SetSndBuf(4u << 20);
        dst.ApplyCheckpoint(ck);
        CHECK(4 == dst.RetransQueueSize());  // segments restored
        CHECK(1u == dst.RetransOutPkts());   // the tag survived

        // Cumulative ACK for everything: the retransmit is retired, so the
        // in-flight retransmission counter must drain to 0.
        now += 20000;
        DeliverRawAck(dst, now, dst.SndNxt());
        std::fprintf(stderr, "[mig-retrans] after full ACK retrans_out=%u\n",
                     dst.RetransOutPkts());
        CHECK(0u == dst.RetransOutPkts());   // red: stays 1 without is_retrans
    }

    /**
     * @brief Migration must drop the out-of-order byte counter with the
     *        buffer it mirrors.
     *
     * The checkpoint carries no reassembly buffer (ooo_ is deliberately
     * dropped: the peer retransmits past the frontier), but ooo_bytes_ was
     * left in place. AdvertisedWindow() reports (window_ - ooo_bytes_) >>
     * rcv_wscale_, so a stale counter permanently shrinks the migrated
     * flow's receive window by data that no longer exists.
     *
     * Red baseline: after ApplyCheckpoint the advertised window stays
     * reduced by the source's ooo_bytes_.
     */
    void TestMigrationClearsOooBytes() {
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn src(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        src.SetPeerMss(kMss);
        src.SetSndBuf(4u << 20);
        const UInt32 wnd_clean = src.AdvertisedWindow();

        // The DESTINATION already holds out-of-order data of its own before the
        // restore. ApplyCheckpoint replaces rcv_nxt_/window_ from the source
        // and drops ooo_, so the destination's byte counter must be dropped
        // with it - otherwise the migrated flow advertises a window reduced by
        // data that belongs to a different connection.
        std::vector<xtcp::buf::BufRef> tx2;
        xtcp::core::TcpConn dst(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 500, 900,
            [&tx2](xtcp::buf::BufRef&& p) { tx2.push_back(std::move(p)); });
        dst.SetPeerMss(kMss);
        dst.SetSndBuf(4u << 20);
        xtcp::core::TimePoint now = 1000;
        const std::vector<Byte> ooo =
            BuildSeg(40000, 443, dst.RcvNxt() + 4 * kMss, 901,
                     static_cast<UInt16>(xtcp::core::kFlagAck), 65535,
                     false, 0, 0, kMss);
        dst.OnSegment(ooo.data(), static_cast<UInt32>(ooo.size()), now);
        const UInt32 wnd_dst_ooo = dst.AdvertisedWindow();
        std::fprintf(stderr, "[mig-ooo] dst clean=%u after ooo=%u\n",
                     wnd_clean, wnd_dst_ooo);
        CHECK(wnd_dst_ooo < wnd_clean);   // the buffer really was charged

        const xtcp::core::TcpConn::ConnCheckpoint ck = src.MakeCheckpoint();
        dst.ApplyCheckpoint(ck);
        const UInt32 wnd_after = dst.AdvertisedWindow();
        std::fprintf(stderr, "[mig-ooo] dst after restore=%u\n", wnd_after);
        // The out-of-order buffer did not travel, so the window is whole again.
        CHECK(wnd_after == wnd_clean);
    }

    /**
     * @brief PipeInFlightBytes must subtract LOST bytes too.
     *
     * Kernel tcp_packets_in_flight() = packets_out - (sacked_out + lost_out)
     * + retrans_out (tcp_h_v66.h:1198-1220). The earlier port subtracted only
     * sacked, so a segment declared lost but not yet retransmitted kept
     * occupying the pipe: a fully-lost flight never looked empty and
     * CA_EVENT_TX_START was suppressed on the retransmit that restarted it.
     *
     * Red baseline: with one 1460-byte segment marked lost (retries == 0,
     * no SACK), the old formula returned 1460 (not 0) and no TX_START fired.
     */
    /**
     * @brief B5-D3 / B6-D1: the CC-visible in-flight count must be
     *        tcp_packets_in_flight, not the raw snd_nxt - snd_una distance.
     *
     * Kernel tcp_enter_loss sets cwnd = tcp_packets_in_flight(tp) + 1
     * (tcp_input_66.c:2176) for a CC that installs an ssthresh hook, and
     * tcp_packets_in_flight() = packets_out - (sacked_out + lost_out) +
     * retrans_out (tcp_66.h:1198-1220). Counting SACKed bytes as in flight
     * inflates the post-loss window.
     *
     * Observable: a passthrough ssthresh hook routes the cut through the
     * plugin branch, so cwnd becomes pipe_pkts + 1.
     *
     * Red baseline (raw distance): with 8 segments outstanding and 7 SACKed,
     * cwnd would be 8 + 1 = 9; the kernel formula gives 1 + 1 = 2.
     */
    void TestCcInflightExcludesSacked() {
        static bool registered = false;
        if (!registered) {
            XtcpCongestionOps ops;
            ops.name = "cc_test_passthrough";
            ops.ssthresh = KccShapeSsthresh;   // passthrough -> plugin branch
            CHECK(xtcp::cc::RegisterCongestionControl(ops));
            registered = true;
        }
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(8u << 20);
        CHECK(conn.SetCongestionControl("cc_test_passthrough"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 8; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        const UInt32 una = conn.SndUna();
        const UInt32 end = conn.SndNxt();
        // SACK the last seven segments: only the head is still unconfirmed.
        now += 1000;
        DeliverRawAck(conn, now, una, xtcp::core::kFlagAck, true, una + kMss, end);
        CHECK(8u * kMss == conn.SndInflight());   // the queue is untouched
        // RTO -> CutCwnd. The kernel marks the head LOST first
        // (tcp_timeout_mark_lost) and only then computes the reduction, so
        // packets_in_flight is 0 here and cwnd = 0 + 1 = 1 for the plugin
        // branch. The point of this case is the SEPARATION of the two bases:
        // ssthresh follows the WINDOW (tcp_reno_ssthresh = max(cwnd>>1, 2))
        // while cwnd follows the live pipe. A raw-distance implementation
        // would report cwnd 9 (8 MSS in flight + 1).
        now += 3000000;
        conn.OnRetransmitTimer(now);
        std::fprintf(stderr,
                     "[B5D3] after RTO cwnd=%u ssthresh=%u (raw-distance cwnd would be 9)\n",
                     conn.Cwnd(), conn.Ssthresh());
        CHECK(1u == conn.Cwnd());          // pipe is empty once the head is LOST
        // The passthrough hook returns the current threshold unchanged, which
        // is what a KCC-shaped CC does (kcc_set_cwnd_to_recover_or_restore
        // owns the window, not ssthresh). The Reno `cwnd >> 1` form belongs to
        // tcp_reno_ssthresh and is covered by TestRenoSsthreshFollowsCwnd.
        CHECK(0x7FFFFFFFu == conn.Ssthresh());
    }
    /**
     * @brief A timeout marks EVERY un-SACKed segment lost, not just the head.
     *
     * Kernel tcp_timeout_mark_lost (tcp_input_66.c:2140-2148) walks the whole
     * retransmit rbtree and calls tcp_mark_skb_lost on every skb that is not
     * SACKED_ACKED:
     *
     *     skb = head;
     *     skb_rbtree_walk_from(skb) {
     *         if (is_reneg) ...
     *         else if (tcp_is_rack(sk) && skb != head &&
     *                  tcp_rack_skb_timeout(tp, skb, 0) > 0)
     *             continue;  // Don't mark recently sent ones lost yet
     *         tcp_mark_skb_lost(sk, skb);
     *     }
     *
     * tcp_mark_skb_lost then does tp->lost_out += tcp_skb_pcount(skb) for
     * every one of them (:1121). Only AFTER that does tcp_enter_loss compute
     * tcp_snd_cwnd_set(tp, tcp_packets_in_flight(tp) + 1) (:2174) - with
     * lost_out covering the whole flight, so the post-timeout window is 1.
     *
     * Marking only the head leaves the rest of the flight inside
     * packets_out, so tcp_packets_in_flight() reports the tail as still in
     * the network and the collapse computes a window far above 1.
     */
    void TestRtoMarksWholeFlightLost() {
        static bool registered = false;
        if (!registered) {
            XtcpCongestionOps ops;
            ops.name = "rto_flight_lost";
            ops.ssthresh = KccShapeSsthresh;   // passthrough -> plugin branch
            CHECK(xtcp::cc::RegisterCongestionControl(ops));
            registered = true;
        }
        std::vector<xtcp::buf::BufRef> tx;
        xtcp::core::TcpConn conn(
            xtcp::core::TcpState::kEstablished, LocalEp(), RemoteEp(), 100, 200,
            [&tx](xtcp::buf::BufRef&& p) { tx.push_back(std::move(p)); });
        conn.SetPeerMss(kMss);
        conn.SetSackOk(true);
        conn.SetSndBuf(8u << 20);
        CHECK(conn.SetCongestionControl("rto_flight_lost"));
        xtcp::core::TimePoint now = 1000;
        for (UInt32 i = 0; i < 4; ++i) {
            std::vector<Byte> buf(kMss, 0x41);
            CHECK(conn.SendData(buf.data(), kMss, now));
        }
        CHECK(4u * kMss == conn.SndInflight());
        // No SACK, no ACK: the whole 4-segment flight is unconfirmed.
        now += 3000000;
        conn.OnRetransmitTimer(now);
        std::fprintf(stderr,
                     "[rto-flight] lost_out=%u retrans_out=%u pipe=%u cwnd=%u\n",
                     conn.LostOutPkts(), conn.RetransOutPkts(),
                     conn.PipeInFlightBytesPublic(), conn.Cwnd());
        // tcp_timeout_mark_lost marks all four; the head is then retransmitted,
        // so retrans_out is 1 and lost_out is 4 (the kernel does NOT clear
        // TCPCB_LOST when a lost segment is retransmitted: tcp_retransmit_skb
        // only sets TCPCB_SACKED_RETRANS).
        CHECK(4u == conn.LostOutPkts());
        CHECK(1u == conn.RetransOutPkts());
        // packets_out(4) - left_out(4) + retrans_out(1) = 1 segment in flight.
        CHECK(kMss == conn.PipeInFlightBytesPublic());
        // tcp_enter_loss computes cwnd BEFORE tcp_retransmit_skb runs, i.e.
        // with retrans_out still 0: packets_in_flight() = 4 - 4 + 0 = 0, so
        // the collapse is tcp_packets_in_flight() + 1 = 1.
        CHECK(1u == conn.Cwnd());
        CHECK(conn.PipeInFlightBytesPublic() == conn.PipeWalkReference());
    }
    /**
     * @brief The O(1) in-flight counters must always equal the queue walk.
     *
     * PipeInFlightBytes() is now maintained incrementally (pipe_sacked_bytes_ /
     * pipe_lost_bytes_ / pipe_retrans_bytes_) instead of walking
     * retrans_queue_ on every ACK - the walk cost ~1.6 ns per queued segment,
     * i.e. ~1.3 us per ACK at a 100 Gbps BDP. The incremental form is only safe
     * if every mutation re-accounts the segment, so this test drives the
     * interesting transitions (send, SACK partial, SACK full, LOST, retransmit,
     * pop) and compares against PipeWalkReference() after each one.
     */
    void TestPipeCountersMatchWalk() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.conn.SetSndBuf(8u << 20);
        for (UInt32 i = 0; i < 8; ++i) {
            h.Send(kMss);
        }
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());
        const UInt32 una = h.conn.SndUna();
        const UInt32 end = h.conn.SndNxt();

        // Partial SACK coverage (two segments of the tail).
        h.now += 1000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true, una + 2 * kMss, end);
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());

        // More SACK coverage (narrows the unsacked part of each segment).
        h.now += 1000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true, una + kMss, end);
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());

        // RTO: marks the head LOST and retransmits it (lost + retries change).
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());

        // Cumulative ACK drains the head (pop).
        h.now += 20000;
        h.Deliver(una + kMss);
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());

        // Full drain.
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());
        CHECK(0u == h.conn.RetransQueueSize());
        CHECK(0u == h.conn.PipeInFlightBytesPublic());
    }

    /**
     * @brief Same invariant, driven by a longer random walk.
     *
     * TestPipeCountersMatchWalk covers the named transitions; this one runs a
     * deterministic pseudo-random sequence of sends, partial/full SACKs, RTOs
     * and cumulative ACKs, checking the O(1) sums against the queue walk after
     * EVERY step. A single missed re-account in any of the ~20 mutation sites
     * shows up here as a divergence.
     */
    void TestPipeCountersRandomized() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.conn.SetSndBuf(16u << 20);
        UInt32 seed = 0x5EED1234u;
        const auto next = [&seed]() -> UInt32 {
            seed = seed * 1664525u + 1013904223u;
            return seed;
        };
        UInt32 checks = 0;
        for (UInt32 step = 0; step < 400; ++step) {
            const UInt32 op = next() % 100;
            if (op < 40) {
                // Send a few segments (may be refused by cwnd/window).
                const UInt32 n = 1 + (next() % 4);
                for (UInt32 i = 0; i < n; ++i) {
                    std::vector<Byte> buf(kMss, 0x41);
                    h.conn.SendData(buf.data(), kMss, h.now);
                }
            } else if (op < 70) {
                // Duplicate ACKs. Emit a BURST of three bare dups (the RFC 5681
                // fast-retransmit threshold), which is what marks the queue head
                // LOST; every third burst uses SACK blocks whose range covers
                // the tail (no gap) instead, exercising the reordering gate.
                const UInt32 una = h.conn.SndUna();
                const UInt32 end = h.conn.SndNxt();
                const bool with_sack = (0 == (next() % 3u)) &&
                                       xtcp::core::SeqLt(una + kMss, end);
                for (UInt32 d = 0; d < 3; ++d) {
                    h.now += 1000;
                    if (with_sack) {
                        h.Deliver(una, xtcp::core::kFlagAck, 65535, true,
                                  una + kMss, end);
                    } else {
                        h.Deliver(una, xtcp::core::kFlagAck, 65535, false);
                    }
                }
            } else if (op < 82) {
                // RTO: marks the head LOST and retransmits.
                h.now += 3000000;
                h.conn.OnRetransmitTimer(h.now);
            } else if (op < 88) {
                // Zero-window persist probe: re-sends the queue front and sets
                // its TCPCB_SACKED_RETRANS (a path that must also re-account
                // the pipe).
                h.now += 1000;
                h.Deliver(h.conn.SndUna(), xtcp::core::kFlagAck, 0);  // window 0
                h.now += 1000000;
                h.conn.OnPersistTimer(h.now);
            } else if (op < 92) {
                // TLP probe: re-sends the queue TAIL, also marking it
                // TCPCB_SACKED_RETRANS without touching `retries`.
                h.now += 2000000;
                h.conn.OnPoll(h.now);
            } else if (op < 96) {
                // Cumulative ACK advancing by one segment (pops the head).
                const UInt32 una = h.conn.SndUna();
                const UInt32 end = h.conn.SndNxt();
                if (xtcp::core::SeqLt(una, end)) {
                    h.now += 20000;
                    h.Deliver(una + kMss);
                }
            } else {
                // Drain everything.
                h.now += 20000;
                h.Deliver(h.conn.SndNxt());
            }
            { const UInt32 a = h.conn.PipeInFlightBytesPublic(); const UInt32 b = h.conn.PipeWalkReference(); if (a != b) { std::fprintf(stderr, "[pipe-random] DIVERGE step=%u inc=%u walk=%u", step, a, b); } CHECK(a == b); }
            ++checks;
            if (0 < g_failures) {
                std::fprintf(stderr, "[pipe-random] diverged at step %u\n", step);
                break;
            }
        }
        std::fprintf(stderr, "[pipe-random] %u consistency checks\n", checks);
        CHECK(300 <= checks);
    }

    void TestKccPipeExcludesLost() {
        // Fully-lost flight, retransmitted: the TX_START gate must see the
        // pre-retransmission pipe (kernel tcp_event_data_sent runs INSIDE
        // __tcp_transmit_skb, i.e. before retrans_out += pcount), which is 0
        // once lost_out is subtracted.
        FsmHarness h;
        h.Send(1460);
        CHECK(1 == g_recTxStart);          // first data on an idle pipe
        // RTO marks the head lost (seg.lost) and then retransmits it. With
        // the old formula (sacked only) the pipe still read 1460 here, so
        // TX_START was suppressed and the retransmit could not restart the
        // congestion state.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        CHECK(2 == g_recTxStart);          // lost excluded -> pipe was empty

        // The retransmitted segment is in flight again (retrans_out), so a
        // following send on the same pipe must NOT be another TX_START.
        h.Send(1460);
        CHECK(2 == g_recTxStart);
    }

    /**
     * @brief TLP retransmission must dispatch CA_EVENT_TX_START when the
     *        pipe it leaves is EMPTY, and must not when it is not.
     *
     * Kernel tcp_event_data_sent runs inside __tcp_transmit_skb for EVERY
     * data skb, the TLP probe included (tcp_output_v66.c:1391-1395), and
     * dispatches CA_EVENT_TX_START only when tcp_packets_in_flight()==0
     * (:167-168). With lost_out subtracted (tcp_h_v66.h:1198-1220), a tail
     * that is fully SACKed or lost leaves the pipe at 0 - so the probe is a
     * TX_START. A live tail (still in flight) is not.
     */
    void TestKccTxStartOnTlp() {
        {
            // Empty pipe at the probe: the only outstanding segment is fully
            // SACKed by a dup-ACK, so PipeInFlightBytes() == 0.
            FsmHarness h;
            h.Warm();                       // srtt_ > 0 -> TLP arms on send
            h.Send(kMss);
            const UInt32 before = g_recTxStart;   // after this send's own TX_START
            const UInt32 una = h.conn.SndUna();
            // Duplicate ACK (frontier unchanged) fully SACKing that segment.
            h.now += 1000;
            h.Deliver(una, xtcp::core::kFlagAck, 65535, true, una, una + kMss);
            // TLP deadline is now + 2*srtt (>= 10ms); the RTO floor is 200ms.
            h.now += 60000;
            h.conn.OnPoll(h.now);
            CHECK(before + 1 == g_recTxStart);   // probe on an empty pipe
            // The probe marked the tail TCPCB_SACKED_RETRANS without touching
            // `retries`; the O(1) pipe sum must still agree with the walk.
            CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());
        }
        {
            // Non-empty pipe: the same probe must NOT dispatch TX_START.
            FsmHarness h;
            h.Warm();
            h.Send(kMss);                        // still in flight, nothing SACKed
            const UInt32 before = g_recTxStart;   // after this send's own TX_START
            h.now += 60000;                      // past 2*srtt, before the RTO
            h.conn.OnPoll(h.now);
            CHECK(before == g_recTxStart);       // pipe non-empty: no TX_START
            CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());
        }
    }

    /**
     * @brief RFC 2883 DSACK must count dup_segs into delivered_pkts EXACTLY
     *        once (kernel tcp_dsack_seen -> state->sack_delivered).
     *
     * Sequence: 3 MSS segments; an RTO retransmits the head (so the sender
     * HAS retransmitted - the kernel gate at tcp_input.c:1027-1032 rejects a
     * DSACK when dsack_dups > total_retrans, and a DSACK is by definition
     * the receiver reporting a SPURIOUS retransmission); a cumulative ACK
     * covering that first segment; then a duplicate ACK at the SAME frontier
     * whose DSACK block covers the just-consumed segment (already popped, so
     * only the dup_segs term can credit it); then a SACK block over the
     * remaining two; then a cumulative ACK covering everything.
     *
     * Expected delivered_total_pkts = 1 (cum-ACK) + 1 (DSACK dup_segs)
     * + 2 (SACK) = 4. Five would mean the DSACKed range was counted twice
     * (dup_segs AND the SACK walk); three would mean the DSACK term was
     * dropped. The dup-ACK path must also EMIT a rate sample (kernel
     * tcp_rate_gen runs on every ACK, tcp_input.c:3939), so g_recCalls
     * advances on each of the four ACKs.
     */
    void TestKccDsackCountsDelivered() {
        FsmHarness h;
        h.Send(kMss);
        h.Send(kMss);
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        const UInt32 end = h.conn.SndNxt();
        CHECK(end == una + 3 * kMss);

        // RTO: mark the head lost and retransmit it. total_retrans becomes 1,
        // which is what makes the later DSACK credible to the kernel gate.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);

        // Cumulative ACK covering the first (retransmitted) segment. This is
        // the connection's first rate sample, so it is degenerate
        // (delivered_pkts == 0) while delivered_total_pkts is already 1.
        g_recCalls = 0;
        h.now += 20000;
        h.Deliver(una + kMss);
        CHECK(1 == g_recCalls);
        CHECK(1ull == g_recLast.delivered_total_pkts);
        CHECK(0u == g_recLast.delivered_pkts);

        // Duplicate ACK at the same frontier with a DSACK block covering the
        // segment that was just cumulatively ACKed. The kernel emits a rate
        // sample for this ACK too (tcp_rate_gen on every ACK).
        h.now += 20000;
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true,
                  una, una + kMss);
        CHECK(2 == g_recCalls);
        CHECK(2ull == g_recLast.delivered_total_pkts);   // +1 dup_segs
        CHECK(1u == g_recLast.delivered_pkts);           // exactly one

        // SACK the two remaining segments (+2).
        h.now += 20000;
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true,
                  una + kMss, end);
        CHECK(3 == g_recCalls);
        CHECK(4ull == g_recLast.delivered_total_pkts);   // +2 (SACK)
        CHECK(2u == g_recLast.delivered_pkts);

        // Cumulative ACK covering everything: the two SACKed segments are
        // already counted, so nothing is added (not 5).
        h.now += 20000;
        h.Deliver(end);
        CHECK(4 == g_recCalls);
        CHECK(4ull == g_recLast.delivered_total_pkts);   // not 5
        CHECK(0u == g_recLast.delivered_pkts);
    }

    /**
     * @brief The PROBE_BW cycle-phase decision must read rs->prior_in_flight_bytes
     *        (the pre-ACK snapshot), never the post-ACK sk->inflight.
     *
     * Kernel kcc_is_next_cycle_phase calls
     * kcc_packets_in_net_at_edt(sk, rs->prior_in_flight)
     * (tcp_kcc_c8bead4.c:5049-5056). The two values differ by exactly the
     * bytes this ACK cleaned, so a BDP target placed between them flips the
     * decision. Both directions are asserted: with the pre-ACK value above
     * the target the phase must end, and with the post-ACK value above the
     * target (pre-ACK below) it must NOT end.
     */
    void TestKccCycleUsesPriorInflight() {
        Driver d(0, 0, 2);            // seed 2 -> first PROBE_BW phase is 0 (gain 1.25x)
        const KccSnapshot probe = ForceProbe(d);
        CHECK(1 == probe.mode);       // PROBE_BW
        CHECK(0 == probe.cycle_idx);  // probe-up phase (gain 320)

        // Target BDP for the probe-up phase, in bytes (same helper the
        // implementation uses).
        const UInt64 target = kcc_bdp_packets(probe.max_bw, probe.min_rtt_us, 320) * kMss;
        CHECK(0 < target);

        RateSample rs;
        rs.pacing_edt_us = 0;
        const UInt64 after_full_length =
            probe.cycle_mstamp_us + probe.min_rtt_us + 1000;

        // (a) pre-ACK in flight ABOVE the target, post-ACK below it:
        // the phase must end (decision follows prior_in_flight).
        rs.prior_in_flight_bytes = target + kMss;
        d.sk.inflight = 0;
        CHECK(1u == xtcp::cc::KccTestIsNextCyclePhase(&d.sk, &rs, after_full_length));

        // (b) mirrored: pre-ACK BELOW the target, post-ACK above it.
        // The phase must NOT end - if the implementation read sk->inflight
        // this row would flip to 1 and catch the regression.
        rs.prior_in_flight_bytes = 0;
        d.sk.inflight = static_cast<UInt32>(target + kMss);
        CHECK(0u == xtcp::cc::KccTestIsNextCyclePhase(&d.sk, &rs, after_full_length));

        // (c) both above the target: end (sanity that the target is real).
        rs.prior_in_flight_bytes = target + kMss;
        d.sk.inflight = static_cast<UInt32>(target + kMss);
        CHECK(1u == xtcp::cc::KccTestIsNextCyclePhase(&d.sk, &rs, after_full_length));

        // (d) B8-D3: the pre-ACK in-flight must also be adjusted by the
        // pacing-queue EDT credit. The gain headroom is kcc_tso_segs_goal
        // (>= 1 segment, audit B6-D3), so place the pre-ACK value one
        // headroom below the target: the credit-free path reaches the target
        // and ends the phase; exactly one credited segment pushes it back
        // below the target, so the phase must NOT end. Forcing the edt_us
        // argument to 0 (the old wiring-removal mutant) flips the second row
        // to 1 and fails here.
        const UInt32 headroom = xtcp::cc::KccTestTsoSegsGoal(&d.sk);
        CHECK(1 <= headroom);
        CHECK(target > static_cast<UInt64>(headroom) * kMss);
        rs.lost = 0;
        rs.prior_in_flight_bytes =
            static_cast<UInt32>(target - static_cast<UInt64>(headroom) * kMss);
        rs.pacing_edt_us = 0;
        CHECK(1u == xtcp::cc::KccTestIsNextCyclePhase(&d.sk, &rs, after_full_length));
        const UInt64 credit_us =
            ((UInt64(1) << 24) + probe.max_bw - 1) / probe.max_bw;
        CHECK(0 < credit_us);
        CHECK(credit_us <= 0xFFFFFFFFull);
        CHECK(1u == ((probe.max_bw * credit_us) >> 24));   // exactly 1 packet
        rs.pacing_edt_us = static_cast<UInt32>(credit_us);
        CHECK(0u == xtcp::cc::KccTestIsNextCyclePhase(&d.sk, &rs, after_full_length));
    }

    void TestKccFsmTfoRequeue() {
        FsmHarness h(xtcp::core::TcpState::kSynSent);
        const Byte cookie[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        h.conn.SetTfoCookie(cookie);
        Byte data[100];
        std::memset(data, 0, sizeof(data));
        h.now = 1000;
        CHECK(h.conn.SendSynWithData(data, sizeof(data)));
        CHECK(201 == h.conn.SndNxt());  // iss+1 + 100 early bytes

        // SYN+ACK acknowledging only the SYN: TFO requeues the early bytes.
        h.now = 20000;
        const std::vector<Byte> synack =
            BuildSeg(40000, 443, 200, 101,
                     static_cast<UInt16>(xtcp::core::kFlagSyn | xtcp::core::kFlagAck));
        h.conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), h.now);
        CHECK(xtcp::core::TcpState::kEstablished == h.conn.State());
        // The requeued early data carries TCPCB_SACKED_RETRANS, so it counts in
        // retrans_out and therefore in the pipe. The O(1) sum must agree with
        // the walk (the segment has is_retrans set but retries == 0 - the pipe
        // term is keyed on the FORMER, like the kernel's retrans_out).
        CHECK(h.conn.PipeInFlightBytesPublic() == h.conn.PipeWalkReference());
        CHECK(0 < h.conn.RetransOutPkts());
        CHECK(h.conn.PipeInFlightBytesPublic() >= 100u);

        h.now = 40000;
        h.Deliver(201);
        CHECK(100ull == g_recLast.delivered_total);
        CHECK(0ull == g_recLast.prior_delivered);
        CHECK(!g_recLast.is_ack_delayed);  // requeued early data is a retransmit
    }

    void TestKccMigrationEpoch() {
        FsmHarness h1;
        h1.Send(100);
        h1.now += 20000;
        h1.Deliver(h1.conn.SndNxt());
        CHECK(100ull == g_recLast.delivered_total);
        h1.Send(100);   // sent_delivered = 100
        const xtcp::core::TcpConn::ConnCheckpoint ckpt = h1.conn.MakeCheckpoint();
        CHECK(1 == ckpt.retrans_queue.size());
        CHECK(0ull == ckpt.retrans_queue[0].sent_delivered);
        CHECK(0 == ckpt.retrans_queue[0].app_limited);
        CHECK(0 == ckpt.retrans_queue[0].is_retrans);

        std::vector<xtcp::buf::BufRef> tx2;
        xtcp::core::TcpConn conn2(xtcp::core::TcpState::kClosed, LocalEp(), RemoteEp(),
                                  100, 200,
                                  [&tx2](xtcp::buf::BufRef&& p) { tx2.push_back(std::move(p)); });
        EnsureRecorderCc();
        conn2.SetPeerMss(kMss);
        conn2.SetCongestionControl("kcc_test_rec");
        conn2.ApplyCheckpoint(ckpt);

        g_recCalls = 0;
        Byte buf[100];
        std::memset(buf, 0, sizeof(buf));
        const xtcp::core::TimePoint now2 = 50000;
        // The restored segment is in flight; new data rides behind it.
        CHECK(conn2.SendData(buf, sizeof(buf), now2));
        const std::vector<Byte> ack =
            BuildSeg(40000, 443, 201, 301, xtcp::core::kFlagAck);  // ACK old segment only
        conn2.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), now2 + 20000);
        CHECK(1 == g_recCalls);
        // New epoch: delivered_total restarted at 0 (not 100+100) and the
        // segment snapshot was not carried across the migration.
        CHECK(100ull == g_recLast.delivered_total);
        CHECK(0ull == g_recLast.prior_delivered);
    }

    /**
     * @brief Short segments (< MSS) count as ONE kernel packet each.
     *
     * Ten 1024-byte segments, one delivered per 20 ms sample: the kernel's
     * tcp_set_skb_tso_segs assigns pcount = 1 to every sub-MSS skb, so each
     * sample reports bw = (1 << 24) / 20000 = 838. The old byte-domain port
     * reported (1024 << 24) / 20000 = 858993 (i.e. 1024/1460 of the kernel
     * value) and only 1024 delivered bytes per sample.
     */
    void TestKccShortSegPacketDomain() {
        Driver d;
        constexpr UInt32 kShort = 1024;
        for (UInt32 i = 0; i < 10; ++i) {
            d.Ack(20000, 20000, kShort, 0, 0);
        }
        const KccSnapshot s = d.Snap();
        const UInt64 expected = (UInt64(1) << 24) / 20000;   // 838
        CHECK(expected == s.max_bw);
        CHECK(858993ull != s.max_bw);   // the old byte-domain value
        CHECK(10ull == s.total_delivered);   // packets, not bytes
    }

    /**
     * @brief Kernel tcp_rate_check_app_limited truth table
     *        (tcp_rate_v66.c:194-207): pending < mss, tx queue idle,
     *        inflight_pkts < cwnd, lost_out <= retrans_out.
     */
    void TestKccAppLimitedTruthTable() {
        using xtcp::cc::IsAppLimited;
        // Baseline: all four conditions hold -> app-limited.
        CHECK(IsAppLimited(0, true, 3, 10, 0, 0, kMss));
        // 1. Pending bytes >= one MSS -> not app-limited.
        CHECK(!IsAppLimited(kMss, true, 3, 10, 0, 0, kMss));
        CHECK(!IsAppLimited(kMss + 1, true, 3, 10, 0, 0, kMss));
        // 2. Host tx queue non-empty -> not app-limited.
        CHECK(!IsAppLimited(0, false, 3, 10, 0, 0, kMss));
        // 3. Inflight >= cwnd (window-limited) -> not app-limited.
        CHECK(!IsAppLimited(0, true, 10, 10, 0, 0, kMss));
        CHECK(!IsAppLimited(0, true, 11, 10, 0, 0, kMss));
        // 4a. A loss outstanding (lost_out > retrans_out) -> not app-limited.
        CHECK(!IsAppLimited(0, true, 3, 10, 2, 0, kMss));
        CHECK(!IsAppLimited(0, true, 3, 10, 3, 2, kMss));
        // Boundary rows: pending == mss-1 still counts as "less than one
        // segment"; inflight == cwnd-1 still fits the window.
        CHECK(IsAppLimited(kMss - 1, true, 3, 10, 0, 0, kMss));
        CHECK(IsAppLimited(0, true, 9, 10, 0, 0, kMss));
        // 4b. RED ROW: every lost packet has been retransmitted
        //     (lost_out == retrans_out) -> app-limited, unlike the old
        //     "cc_.lost == 0" test which stayed conservative forever.
        CHECK(IsAppLimited(0, true, 3, 10, 2, 2, kMss));
        CHECK(IsAppLimited(0, true, 3, 10, 5, 7, kMss));
        // MSS 0 cannot classify anything.
        CHECK(!IsAppLimited(0, true, 3, 10, 0, 0, 0));
    }

    /**
     * @brief FSM-level: a fully retransmitted loss still marks the send
     *        app-limited (kernel lost_out <= retrans_out), while a lost
     *        packet that is NOT retransmitted does not.
     */
    void TestKccFsmAppLimitedLostRetransmitted() {
        {
            // Zero-window persist re-probe retransmits the lost byte, so
            // lost_out == retrans_out afterwards: a later send on the idle
            // pipe must latch app_limited.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.Deliver(h.conn.SndUna(), xtcp::core::kFlagAck, 0);  // zero window
            h.Send(100);                                          // arms persist
            h.now += 1100000;
            h.conn.OnPoll(h.now);                                 // re-probe (retransmit)
            g_recMarker = 0;
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());   // ACK clears the loss bookkeeping
            h.Send(100);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(1u == g_recLast.is_app_limited);
        }
        {
            // Fresh idle pipe, nothing lost: app-limited.
            FsmHarness h;
            h.Warm();
            h.Send(100);
            h.now += 20000;
            h.Deliver(h.conn.SndNxt());
            CHECK(1u == g_recLast.is_app_limited);
        }
        {
            // Buffered backlog (pending >= mss): never app-limited.
            FsmHarness h;
            h.Warm();
            h.conn.SetSndBuf(64 * 1024);
            h.Deliver(h.conn.SndUna(), xtcp::core::kFlagAck, 0);  // zero window
            const UInt32 calls_before = g_recCalls;
            h.Send(4 * kMss);   // all buffered behind the closed window
            // The buffered path emits no data, so it produces no rate
            // sample either: nothing is app-limited about a full backlog.
            CHECK(calls_before == g_recCalls);
        }
    }

    /**
     * @brief MSS multiples: the packet-domain estimate is exactly the
     *        byte-domain rate divided by MSS (both floors), so scaling the
     *        packet rate by MSS reproduces the byte rate up to the floor
     *        error of one segment-rate unit (< MSS bytes/us<<24).
     */
    void TestKccMssMultipleEquivalence() {
        for (UInt32 k = 1; k <= 8; ++k) {
            Driver d;
            const UInt32 delivered_bytes = k * kMss;
            d.Ack(20000, 20000, delivered_bytes, 0, 0);
            const KccSnapshot s = d.Snap();
            const UInt64 pkts = (UInt64(k) << 24) / 20000;
            const UInt64 bytes = (UInt64(delivered_bytes) << 24) / 20000;
            CHECK(pkts == s.max_bw);
            // |pkts*mss - bytes| < mss: the only difference is the floor of
            // the packet-domain division (exact when mss divides the product).
            const UInt64 scaled = pkts * kMss;
            const UInt64 diff = (scaled > bytes) ? (scaled - bytes) : (bytes - scaled);
            CHECK(diff < kMss);
        }
    }

    /**
     * @brief Kernel tcp_count_delivered must not charge SACKed bytes twice.
     *
     * Three MSS segments: a duplicate ACK SACKs the second and third
     * (delivered += 2), then the cumulative ACK covers all three. Kernel
     * tcp_clean_rtx_queue (tcp_input.c:3312-3315) skips tcp_count_delivered
     * for skbs tagged SACKED_ACKED, so only the first segment is counted
     * again: total = 1 (warm-up) + 2 (SACK) + 1 (cum-ACK) = 4. Counting the
     * full pkt_count at the pop would report 6.
     */
    void TestKccSackDeliveredNoDoubleCount() {
        FsmHarness h;
        h.Warm();                    // delivered_pkts = 1
        h.Send(kMss);
        h.Send(kMss);
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        const UInt32 end = h.conn.SndNxt();
        h.now += 20000;
        // Duplicate ACK (frontier unchanged) SACKing segments 2 and 3.
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true, una + kMss, end);
        g_recCalls = 0;
        h.now += 20000;
        // Cumulative ACK covering all three (two of them already SACKed).
        h.Deliver(end);
        CHECK(1 == g_recCalls);
        CHECK(4ull == g_recLast.delivered_total_pkts);
        CHECK(6ull != g_recLast.delivered_total_pkts);
    }

    /**
     * @brief Recovery-state differential: ca_state / prev_ca_state /
     *        prior_cwnd / packet_conservation must match the ref core.
     *
     * Before the ref block existed the reference left all four at 0, so a
     * recovery-transition test could not compare anything: the port could
     * diverge (cwnd growth during packet conservation, missing
     * Recovery->Open restore) and the differential stayed green.
     */
    void TestKccRecoveryDifferential() {
        Driver d(0, 0, 2);
        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(20000);
        }
        // Enter Recovery (kernel CA_Recovery = 3). The transition sample
        // latches conservation; the NEXT delivered round is a round_start and
        // kernel kcc_update_bw (tcp_kcc.c:4336) clears it. Staying at 1 for the
        // whole episode would freeze the window (audit B8-D1).
        d.SetPriorCwnd(d.sk.snd_cwnd);
        d.SetCaState(3);
        d.Round(20000);
        CheckFullSnapshot(d);
        CHECK(1u == d.Snap().packet_conservation);   // latched on transition
        CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
        for (UInt32 i = 1; i < 20; ++i) {
            d.Round(20000);
            CheckFullSnapshot(d);
            CHECK(0u == d.Snap().packet_conservation);   // cleared by round_start
            CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
        }
        // Back to Open: cwnd = max(cwnd, prior_cwnd), conservation cleared.
        d.SetCaState(0);
        for (UInt32 i = 0; i < 20; ++i) {
            d.Round(20000);
            CheckFullSnapshot(d);
            CHECK(0u == d.Snap().packet_conservation);
            CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
        }
        // CA_Loss (4) behaves like Recovery for the port's conservation gate.
        d.SetCaState(4);
        for (UInt32 i = 0; i < 10; ++i) {
            d.Round(20000);
            CheckFullSnapshot(d);
            CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
        }

        // B8-D8: CA_CWR (2) must be exercised too, otherwise the CWR branch of
        // kcc_set_cwnd_to_recover_or_restore (and the packet_conservation gate
        // keyed on `ca_state == 3`) is never driven and the 37-field
        // differential is a tautology for those rows. CWR -> Recovery must
        // NOT latch conservation again (the reduction snapshot already
        // exists), and CWR -> Open must restore prior_cwnd.
        {
            Driver c(0, 0, 2);
            for (UInt32 i = 0; i < 6; ++i) {
                c.Round(20000);
            }
            const UInt32 cwnd_before = c.sk.snd_cwnd;
            c.SetCaState(2);             // CA_CWR
            for (UInt32 i = 0; i < 8; ++i) {
                c.Round(20000);
                CheckFullSnapshot(c);
                CHECK(kcc_core_cwnd_segs(&c.ref) == static_cast<s64>(c.sk.snd_cwnd));
            }
            // CWR is not a "first Recovery entry": conservation stays 0.
            CHECK(0u == c.Snap().packet_conservation);
            CHECK(2u == c.Snap().ca_state);
            // CWR -> Open does NOT restore prior_cwnd: the kernel gate is
            // `prev_state >= TCP_CA_Recovery` (3), and CWR is 2
            // (tcp_kcc.c:4006). The window simply keeps growing.
            c.SetPriorCwnd(cwnd_before + 20);
            c.SetCaState(0);
            c.Round(20000);
            CheckFullSnapshot(c);
            CHECK(static_cast<UInt32>(cwnd_before + 20) != c.sk.snd_cwnd);
            CHECK(kcc_core_cwnd_segs(&c.ref) == static_cast<s64>(c.sk.snd_cwnd));
        }

        // B8-D4: kernel kcc_set_cwnd_to_recover_or_restore restores
        // cwnd = max(cwnd, prior_cwnd) on Recovery -> Open
        // (tcp_kcc.c:4007-4009). In the scenario above prior_cwnd equals the
        // current window, so the branch body never fires. Use a short history
        // that leaves full_bw_reached == 0: the post-restore additive branch
        // then only grows when cwnd < target, so pinning prior_cwnd AT the
        // BDP target makes the restored value survive untouched and the
        // assertion observes the branch body itself.
        {
            Driver r(0, 0, 2);
            r.Round(20000);              // sample 1: STARTUP, full_bw armed
            r.SetCaState(3);
            r.Round(20000);              // sample 2: Open -> Recovery entry
            const KccSnapshot pre = r.Snap();
            CHECK(0 == pre.mode);        // still STARTUP
            CHECK(0u == pre.full_bw_reached);
            CHECK(1u == pre.packet_conservation);
            CHECK(3u == pre.prev_ca_state);
            // The cwnd target is the BDP plus the quantization budget
            // (Linux bbr_set_cwnd -> bbr_quantization_budget); ack
            // aggregation is still 0 because full_bw is not reached.
            const UInt64 restore_target = kcc_quantization_budget(
                kcc_bdp_packets(pre.max_bw, pre.min_rtt_us, pre.cwnd_gain),
                kcc_tso_segs_goal(&r.ref));
            CHECK(6 < restore_target);
            CHECK(restore_target <= 0xFFFFFFFFull);
            r.sk.snd_cwnd = 6;
            r.ref.cwnd_segs = 6;
            r.ref.congestion_window_bytes = 6 * kMss;
            r.SetPriorCwnd(static_cast<UInt32>(restore_target));
            r.SetCaState(0);
            r.Round(20000);              // sample 3: Recovery -> Open restore
            CHECK(static_cast<UInt32>(restore_target) == r.sk.snd_cwnd);
            CheckFullSnapshot(r);
            CHECK(0u == r.Snap().packet_conservation);
            CHECK(kcc_core_cwnd_segs(&r.ref) == static_cast<s64>(r.sk.snd_cwnd));
        }
        CHECK(0u == g_failures);
    }

    void TestKccDifferentialNewFields() {
        Driver d(0, 0, 2);
        // B8-D3: keep ONE segment in flight. With the old 20-segment pipe a
        // pacing-queue credit of at most one packet could never move any
        // decision, so the EDT wiring had zero falsifiable coverage.
        d.flight = kMss;
        UInt32 seed = 0x12345678;
        const auto next = [&seed]() -> UInt32 {
            seed = seed * 1664525u + 1013904223u;
            return seed;
        };
        // Zero / minimal / partial / full credit rows (edt_us is the pacing
        // queue depth fed to both the port and the reference core).
        static const UInt32 kEdtGrid[] = {0, 1, 2, 3, 4000};
        for (UInt32 i = 0; i < 3000; ++i) {
            UInt32 rtt_us = 20000 + (i % 1000) * 3 + (next() % 2000);
            if (i < 200) {
                rtt_us = 30000 - i * 5;
            }
            const UInt32 delivered = (1 + (next() % 4)) * kMss;
            const UInt32 lost = (0 == (i % 700)) ? delivered : 0;
            const UInt32 interval_us = 10000 + (next() % 5000);
            UInt64 prior;
            if (i < 500) {
                prior = d.total;             // ACK-clocked rounds
            } else if (0 == (i % 3)) {
                prior = d.total;             // explicit boundary
            } else if (1 == (i % 3)) {
                prior = 0;                   // same burst
            } else {
                prior = d.total / 2;         // stale snapshot (no round)
            }
            const bool delayed = (0 == (i % 11));
            const bool app = (0 == (i % 17));
            d.edt_us = kEdtGrid[i % (sizeof(kEdtGrid) / sizeof(kEdtGrid[0]))];
            d.Ack(rtt_us, interval_us, delivered, lost, prior, delayed, app);
            CheckFullSnapshot(d);
            CHECK(kcc_core_cwnd_segs(&d.ref) == static_cast<s64>(d.sk.snd_cwnd));
            CHECK(kcc_core_pacing_rate(&d.ref) == static_cast<s64>(d.sk.pacing_rate));
            if (0 < g_failures) {
                std::fprintf(stderr, "new-field differential mismatch at step %u\n", i);
                break;
            }
        }
    }

    /**
     * @brief B8-D5: the jitter EWMA must be evaluated in 64 bits.
     *
     * Kernel tcp_kcc.c:4500-4503 widens the product to (u64) before the
     * division; the port/oracle used 32-bit arithmetic, so
     * jitter_ewma*7 + raw_jitter wrapped once jitter_ewma >= 613,566,582
     * (min_rtt >= ~613.6 s is reachable: RTT samples are capped at 3600 s).
     *
     * A long RTT seed plus one low sample drives x_est near 1 s while the
     * min_rtt confirmation gates keep min_rtt at 700 s; every following
     * 700 s sample then contributes raw_jitter ~= 699,000,000 us. The
     * expected value is recomputed here with the u64 formula from the
     * OBSERVED pre-ACK x_est, so a 32-bit wrap shows up as a mismatch.
     */
    void TestKccJitterEwmaWideMul() {
        Driver d(700000000u, 0, 2);
        const auto step = [&d](UInt32 rtt_us) {
            const KccSnapshot before = d.Snap();
            const UInt64 x_us = before.x_est >> 10;
            UInt64 raw = (rtt_us > x_us) ? (rtt_us - x_us) : (x_us - rtt_us);
            if (0xFFFFFFFFull < raw) {
                raw = 0xFFFFFFFFull;
            }
            d.Round(rtt_us);
            const KccSnapshot after = d.Snap();
            UInt64 want;
            if (0 == before.sample_cnt) {
                want = rtt_us >> 2;                  // kJitterSeedShift
                if (0 == want) {
                    want = 1;
                }
            } else if (1 == before.sample_cnt) {
                want = raw;
            } else {
                want = (static_cast<UInt64>(before.jitter_ewma) * 7u + raw) / 8u;
            }
            const UInt64 cap =
                (before.min_rtt_us > 500000u) ? before.min_rtt_us : 500000u;
            if (cap < want) {
                want = cap;
            }
            CHECK(after.jitter_ewma == want);
            CHECK(d.ref.jitter_ewma == after.jitter_ewma);
        };
        step(700000000u);       // seed: jitter = rtt >> 2 = 175,000,000
        step(1000000u);         // x_est collapses to 1 s (raw ~= 699,000,000)
        for (UInt32 i = 0; i < 25; ++i) {
            step(700000000u);
        }
        const KccSnapshot s = d.Snap();
        CHECK(600000000u < s.jitter_ewma);   // 32-bit path stays below ~537M
    }

    /**
     * @brief B8-D6: the reference core must not divide by zero when a test
     *        harness leaves ref.mss unset (the port guards with mss > 0).
     */
    void TestKccOracleZeroMss() {
        kcc_core ref;
        kcc_core_init(&ref);
        ref.mss = 0;
        ref.min_rtt_us = 20000;
        ref.has_seen_rtt = 0;
        kcc_core_on_ack_pkts(&ref, 20000, 1, 20000, kMss, kMss, 0, 0, 1, 0, 0, 0);
        CHECK(0 < kcc_core_cwnd_segs(&ref));
        CHECK(0 < kcc_core_pacing_rate(&ref));
        CHECK(0 == ref.has_seen_rtt);   // boot-rate path skipped, like the port
    }

    // ---- Batch 7: app_limited / delivered accounting ----

    /**
     * @brief A1: kernel tcp_rate_check_app_limited cond3 compares
     *        tcp_packets_in_flight with snd_cwnd (tcp_rate_66.c:203), and the
     *        marker itself is `tp->delivered + tcp_packets_in_flight`
     *        (tcp_rate_66.c:205-206) in the PACKET domain. A TSO segment
     *        (3 MSS in one skb, pkt_count 3) must contribute 3 packets, not
     *        4380 bytes, and cond3 must read 3 < cwnd.
     */
    void TestB7A1AppLimitedCond3Packets() {
        FsmHarness h;
        h.Warm();                       // delivered_pkts = 1
        h.conn.SetSndBuf(1u << 20);
        h.conn.SetTsoTx(true);
        // One 3-packet super-segment on an otherwise idle pipe.
        h.Send(3 * kMss);
        CHECK(1 == h.conn.RetransQueueSize());   // TSO direct: one skb
        // A one-byte send runs MaybeMarkAppLimited with inflight = 4380 B
        // = 3 packets. cond3 (3 < 10) holds, so the marker latches at
        // delivered_pkts + 3 = 4. A byte-domain cond3 would read 4380 and
        // refuse to latch (0), and a byte-domain marker would be 4381.
        h.Send(1);
        const UInt32 marker = h.conn.AppLimitedMarker();
        const UInt64 delivered = h.conn.DeliveredPkts();
        std::fprintf(stderr, "[B7A1] marker=%u delivered=%llu lost=%u retx=%u\n",
                     marker, static_cast<unsigned long long>(delivered),
                     h.conn.LostOutPkts(), h.conn.RetransOutPkts());
        CHECK(0 != marker);                               // cond3 latched
        CHECK(static_cast<UInt32>(delivered) + 3 == marker);  // packet domain
    }

    /**
     * @brief A2/A3: kernel tcp_rate_gen clears app_limited on EVERY ACK
     *        (tcp_rate_66.c:123-125), a SACK-only dup-ACK included. A3 is
     *        the symptom: the marker must be gone BEFORE the next segment's
     *        send-time snapshot (tcp_rate_66.c:69), so its rate sample must
     *        report is_app_limited = 0.
     */
    void TestB7A2MarkerClearedOnEveryAck() {
        FsmHarness h;
        h.Warm();                       // delivered_pkts = 1, marker cleared
        // One segment on an idle pipe: cond3 (0 < cwnd) holds, so the marker
        // latches at delivered_pkts + 0 = 1.
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        const UInt32 marker = h.conn.AppLimitedMarker();
        std::fprintf(stderr, "[B7A2] marker=%u una=%u end=%u\n", marker, una,
                     h.conn.SndNxt());
        CHECK(1u == marker);
        // SACK-only dup-ACK covering that segment: delivered_pkts 1 -> 2
        // passes the marker, so the kernel clears it on THIS ACK (no
        // cumulative advance involved).
        h.now += 20000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true, una, una + kMss);
        std::fprintf(stderr, "[B7A2] after SACK-only: marker=%u delivered=%llu\n",
                     h.conn.AppLimitedMarker(),
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()));
        CHECK(2ull == h.conn.DeliveredPkts());
        CHECK(0 == h.conn.AppLimitedMarker());   // red: still latched

        // A3: the RTO retransmit of that (SACKed but un-ACKed) segment takes
        // its is_app_limited snapshot now; the ACK that pops it reports it.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        g_recCalls = 0;
        g_recLast = RateSample();
        h.now += 20000;
        h.Deliver(h.conn.SndNxt());
        std::fprintf(stderr, "[B7A2] popped sample is_app_limited=%u\n",
                     g_recLast.is_app_limited);
        CHECK(1 <= g_recCalls);
        CHECK(0u == g_recLast.is_app_limited);   // red: 1 (stale marker)
    }
    /**
     * @brief A4: kernel tcp_sacktag_one drops a LOST segment from lost_out
     *        when the SACK block fully covers it (tcp_input_66.c:1414-1417;
     *        the retransmitted variant at :1392-1396 clears both LOST and
     *        SACKED_RETRANS). The port only decremented lost_out_pkts_ when
     *        the segment was popped, so a SACKed loss stayed counted forever
     *        and app_limited cond4 (lost_out <= retrans_out) never held.
     */
    void TestB7A4SackClearsLostOut() {
        FsmHarness h;
        h.Warm();
        h.conn.SetSndBuf(1u << 20);
        for (UInt32 i = 0; i < 4; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        // RTO marks the WHOLE un-SACKed flight lost (kernel
        // tcp_timeout_mark_lost walks the rbtree, tcp_input_66.c:2140-2148)
        // and retransmits the head.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        std::fprintf(stderr, "[B7A4] after RTO lost_out=%u retrans_out=%u\n",
                     h.conn.LostOutPkts(), h.conn.RetransOutPkts());
        CHECK(4 == h.conn.LostOutPkts());
        // The peer SACKs the retransmitted head completely: the kernel
        // removes it from lost_out (and from retrans_out). The three still
        // un-SACKed tail segments stay lost until they are delivered.
        h.now += 20000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true, una, una + kMss);
        std::fprintf(stderr, "[B7A4] after SACK: lost_out=%u retrans_out=%u\n",
                     h.conn.LostOutPkts(), h.conn.RetransOutPkts());
        CHECK(3 == h.conn.LostOutPkts());
        // cond4 of tcp_rate_check_app_limited must be satisfiable again once
        // the tail drains: SACK the remaining three.
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true,
                  una + kMss, una + 4 * kMss);
        std::fprintf(stderr, "[B7A4] after tail SACK: lost_out=%u retrans_out=%u\n",
                     h.conn.LostOutPkts(), h.conn.RetransOutPkts());
        CHECK(0 == h.conn.LostOutPkts());
        CHECK(h.conn.LostOutPkts() <= h.conn.RetransOutPkts());
    }
    /**
     * @brief B1: an EMPTY DSACK block (start == end) must be rejected
     *        before any accounting (tcp_input_66.c:1011-1012
     *        `if (!before(start_seq, end_seq)) return 0;`). The port counted
     *        dup_segs = 1 for it.
     */
    void TestB7B1EmptyDsackIgnored() {
        FsmHarness h;
        h.Warm();                     // delivered_pkts = 1
        h.Send(kMss);
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        // A retransmission is required for the DSACK to be credible at all.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        h.now += 20000;
        h.Deliver(una + kMss);        // cum-ACK the retransmitted head
        const UInt64 before = h.conn.DeliveredPkts();
        const UInt32 dups_before = h.conn.DsackDups();
        h.now += 20000;
        // Empty block at the frontier: seq_len == 0.
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true,
                  una + kMss, una + kMss);
        std::fprintf(stderr, "[B7B1] delivered %llu -> %llu dups %u -> %u\n",
                     static_cast<unsigned long long>(before),
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()),
                     dups_before, h.conn.DsackDups());
        CHECK(before == h.conn.DeliveredPkts());   // red: +1
        CHECK(dups_before == h.conn.DsackDups());  // red: +1
    }

    /**
     * @brief B2: a REVERSED block (right < left) must be rejected before it
     *        can poison dsack_dups_ (tcp_input_66.c:1011 before() runs
     *        first). The port accumulated the dups first and filtered after,
     *        so a later LEGITIMATE DSACK was gated out.
     */
    void TestB7B2ReversedBlockDoesNotPoisonGate() {
        FsmHarness h;
        h.Warm();
        h.Send(kMss);
        h.Send(kMss);
        const UInt32 una = h.conn.SndUna();
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);   // total_retrans = 1
        h.now += 20000;
        h.Deliver(una + kMss);             // cum-ACK the retransmitted head
        const UInt64 base = h.conn.DeliveredPkts();
        const UInt32 dups = h.conn.DsackDups();
        // Reversed block: sr < sl. Must be ignored entirely.
        h.now += 20000;
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true,
                  una + kMss, una);
        std::fprintf(stderr, "[B7B2] after reversed: dups=%u delivered=%llu\n",
                     h.conn.DsackDups(),
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()));
        CHECK(dups == h.conn.DsackDups());          // red: +1 poisoned
        CHECK(base == h.conn.DeliveredPkts());
        // A genuine DSACK for the retransmitted head must still be credited.
        h.now += 20000;
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true,
                  una, una + kMss);
        std::fprintf(stderr, "[B7B2] after genuine DSACK: delivered=%llu (expect %llu)\n",
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()),
                     static_cast<unsigned long long>(base + 1));
        CHECK(base + 1 == h.conn.DeliveredPkts());  // red: gate poisoned
    }

    /**
     * @brief A D-SACK must not undo an episode that has no undo candidate.
     *
     * Kernel tcp_try_undo_dsack (tcp_input_66.c:2580-2592):
     *
     *     if (tp->undo_marker && !tp->undo_retrans) {
     *         ...
     *         tcp_undo_cwnd_reduction(sk, false);
     *         return true;
     *     }
     *     return false;
     *
     * The undo_marker gate is what makes an ECE-marked episode
     * un-undoable: tcp_fastretrans_alert part A clears the candidate when
     * congestion is PROVEN (tcp_input_66.c:2986-2987, mirrored by the port's
     * `prior_ssthresh_ = 0; undo_marker_ = false;` at tcp_fsm.cpp:3172-3175).
     * Without the gate a duplicate that happens to overlap a retransmitted
     * range restores the pre-cut window even though ECN proved the cut was
     * justified - the connection then re-inflates and overshoots.
     */
    void TestDsackDoesNotUndoWithoutMarker() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.Warm();
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 8; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        // Let the flight age, then SACK everything except the head: the pipe
        // is 1 segment, and the recovery cut will land below the saved
        // prior_cwnd_ so a wrongly-fired undo would be visible.
        h.now += 20000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true,
                  una + kMss, una + 8 * kMss);
        // Enter recovery WITHOUT SACK: the entry saves prior_cwnd_ and keeps
        // the undo candidate (tcp_fsm.cpp:3961 gates on opt->sack_count).
        for (UInt32 i = 0; i < 3; ++i) {
            h.now += 1000;
            h.Deliver(una);
        }
        CHECK(h.conn.FastRecovery());
        const UInt32 cwnd_cut = h.conn.Cwnd();
        // A SACK block then arrives during the no-SACK entry: the loss is
        // confirmed after all, so the port clears the undo candidate
        // (tcp_fsm.cpp:4035, mirroring the kernel's proof that removes the
        // spurious-loss hypothesis).
        h.now += 1000;
        h.Deliver(una, xtcp::core::kFlagAck, 65535, true,
                  una + 6 * kMss, una + 7 * kMss);
        const UInt32 cwnd_sack = h.conn.Cwnd();
        const UInt32 ssth_sack = h.conn.Ssthresh();
        // A D-SACK for the retransmitted head arrives: the cumulative ACK has
        // moved past it (ack == una + kMss) and the block sits entirely below
        // that frontier, which is the shape tcp_dsack_seen accepts. Kernel
        // tcp_try_undo_dsack requires tp->undo_marker, which is now clear, so
        // it must refuse and leave the reduction in place.
        h.now += 1000;
        h.Deliver(una + kMss, xtcp::core::kFlagAck, 65535, true, una, una + kMss);
        std::fprintf(stderr,
                     "[dsack-nomarker] cut cwnd=%u -> after SACK cwnd=%u ssth=%u "
                     "-> after D-SACK cwnd=%u ssth=%u fr=%d\n",
                     cwnd_cut, cwnd_sack, ssth_sack, h.conn.Cwnd(),
                     h.conn.Ssthresh(), h.conn.FastRecovery() ? 1 : 0);
        // No undo candidate: the reduction stands untouched.
        CHECK(cwnd_sack == h.conn.Cwnd());
        CHECK(ssth_sack == h.conn.Ssthresh());
    }

    /** @brief Raw ACK carrying TWO SACK blocks (RFC 2018 option, 40 bytes). */
    std::vector<Byte> BuildSegTwoSack(UInt16 sport, UInt16 dport, UInt32 seq,
                                      UInt32 ack, UInt16 flags, UInt16 window,
                                      UInt32 sl0, UInt32 sr0,
                                      UInt32 sl1, UInt32 sr1) {
        // TCP 20 + two NOPs + SACK option (2 + 16) = 40 bytes, so the data
        // offset is 10 * 4.
        std::vector<Byte> seg(40, 0);
        Byte* t = seg.data();
        t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
        t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = 0xA0;   // data offset 10 * 4 = 40
        t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                                  ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                                  ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                                  ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                                  ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00) |
                                  ((flags & xtcp::core::kFlagEce) ? 0x40 : 0x00));
        t[14] = static_cast<Byte>(window >> 8);
        t[15] = static_cast<Byte>(window & 0xFF);
        t[20] = 1; t[21] = 1;   // NOP, NOP
        t[22] = 5; t[23] = 18;  // SACK, length 18: two 8-byte blocks
        t[24] = static_cast<Byte>(sl0 >> 24); t[25] = static_cast<Byte>(sl0 >> 16);
        t[26] = static_cast<Byte>(sl0 >> 8);  t[27] = static_cast<Byte>(sl0 & 0xFF);
        t[28] = static_cast<Byte>(sr0 >> 24); t[29] = static_cast<Byte>(sr0 >> 16);
        t[30] = static_cast<Byte>(sr0 >> 8);  t[31] = static_cast<Byte>(sr0 & 0xFF);
        t[32] = static_cast<Byte>(sl1 >> 24); t[33] = static_cast<Byte>(sl1 >> 16);
        t[34] = static_cast<Byte>(sl1 >> 8);  t[35] = static_cast<Byte>(sl1 & 0xFF);
        t[36] = static_cast<Byte>(sr1 >> 24); t[37] = static_cast<Byte>(sr1 >> 16);
        t[38] = static_cast<Byte>(sr1 >> 8);  t[39] = static_cast<Byte>(sr1 & 0xFF);
        return seg;
    }

    /**
     * @brief DSACK-of-OFO: with two SACK blocks the FIRST block is a duplicate
     *        when it sits inside the second.
     *
     * Kernel tcp_check_dsack (tcp_input_66.c:1274-1284):
     *
     *     if (before(start_seq_0, TCP_SKB_CB(ack_skb)->ack_seq)) {
     *         ...                                  // plain D-SACK
     *     } else if (num_sacks > 1) {
     *         u32 end_seq_1   = sp[1].end_seq;
     *         u32 start_seq_1 = sp[1].start_seq;
     *         if (after(end_seq_0, end_seq_1) ||
     *             before(start_seq_0, start_seq_1))
     *             return false;
     *         ...                                  // DSACK of O-FO
     *     } else {
     *         return false;
     *     }
     *
     * The port only implemented the first arm: a block at/below the cumulative
     * ACK. A peer that reports the duplicate as the first of two blocks - the
     * shape Linux itself sends when the duplicate is out-of-order - was
     * therefore not recognized at all, so the spurious retransmission was
     * never credited and the undo never became possible.
     */
    void TestDsackOfOutOfOrderRecognized() {
        FsmHarness h;
        h.conn.SetSackOk(true);
        h.Warm();
        h.conn.SetSndBuf(4u << 20);
        for (UInt32 i = 0; i < 6; ++i) {
            h.Send(kMss);
        }
        const UInt32 una = h.conn.SndUna();
        // A retransmission so total_retrans_pkts_ can carry a DSACK.
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        CHECK(1 == h.conn.RetransmitCount());
        const UInt64 base = h.conn.DeliveredPkts();
        const UInt32 dups = h.conn.DsackDups();
        // The cumulative ACK does NOT advance (ack == una), so block0
        // [una, una+kMss) is NOT below the frontier: the kernel's FIRST arm
        // (before(start_seq_0, ack_seq)) is false and only the multi-block arm
        // can classify it. block0 sits INSIDE block1, which is exactly the
        // DSACK-of-O-FO shape a peer produces for an out-of-order duplicate.
        const std::vector<Byte> seg = BuildSegTwoSack(
            443, 40000, 201, una, xtcp::core::kFlagAck, 65535,
            una, una + kMss, una, una + 3 * kMss);
        h.now += 20000;
        h.conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()), h.now);
        std::fprintf(stderr,
                     "[dsack-ofo] delivered %llu -> %llu dups %u -> %u\n",
                     static_cast<unsigned long long>(base),
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()),
                     dups, h.conn.DsackDups());
        // Kernel accepts block0 as a duplicate: dsack_dups moves by one and
        // tcp_dsack_seen credits dup_segs (= 1) to state->sack_delivered.
        CHECK(dups + 1 == h.conn.DsackDups());
    }

    /**
     * @brief B3: a DSACK block longer than tp->max_window is dubious and
     *        must be rejected (tcp_input_66.c:1015-1017). tp->max_window is
     *        the largest receive window the peer ever advertised
     *        (tcp_input_66.c:6409 at the handshake, :3596-3597 afterwards),
     *        so a real handshake advertising 300 bytes pins it to 300.
     *
     * The block is 400 bytes: longer than max_window (the kernel rejects it)
     * yet a single segment (dup_segs = 1), so the old code - which had no
     * max_window test - credited +1 because its event-domain gate
     * (dsack_dups 1 <= retransmit_count_ 1) happened to pass.
     */
    void TestB7B3OversizedDsackRejected() {
        FsmHarness h(xtcp::core::TcpState::kSynSent);
        // Handshake advertising a 300-byte window with no window scale, so
        // snd_wnd_ = max_window_ = 300 (tcp_input_66.c:6409).
        h.Deliver(101, static_cast<UInt16>(xtcp::core::kFlagSyn | xtcp::core::kFlagAck),
                  300, false, 0, 0, 200);
        CHECK(xtcp::core::TcpState::kEstablished == h.conn.State());
        CHECK(300 == h.conn.SndWnd());
        // One window-limited segment, then an RTO retransmits it: one
        // retransmission event, one packet.
        h.Send(300);
        CHECK(1 == h.conn.RetransQueueSize());
        const UInt32 una = h.conn.SndUna();
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        std::fprintf(stderr, "[B7B3] events=%u total_retrans_pkts=%u snd_wnd=%u\n",
                     h.conn.RetransmitCount(), h.conn.TotalRetransPkts(),
                     h.conn.SndWnd());
        CHECK(1 == h.conn.RetransmitCount());
        h.now += 20000;
        // Every ACK keeps advertising the same 300-byte window, so
        // tp->max_window stays 300 (a 65535 ACK would legitimately grow it).
        h.Deliver(una + 300, xtcp::core::kFlagAck, 300);
        const UInt64 base = h.conn.DeliveredPkts();
        const UInt32 dups = h.conn.DsackDups();
        // 400-byte block ending at the frontier: seq_len 400 > max_window
        // 300 -> dubious, rejected BEFORE dsack_dups moves.
        h.now += 20000;
        h.Deliver(una + 300, xtcp::core::kFlagAck, 300, true,
                  una + 300 - 400, una + 300);
        std::fprintf(stderr, "[B7B3] delivered %llu -> %llu dups %u -> %u\n",
                     static_cast<unsigned long long>(base),
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()),
                     dups, h.conn.DsackDups());
        CHECK(base == h.conn.DeliveredPkts());   // red: +1
        CHECK(dups == h.conn.DsackDups());       // no counter movement
    }
    /**
     * @brief B4: the DSACK credibility gate compares dsack_dups against
     *        tp->total_retrans in the PACKET domain (tcp_output_66.c:3325
     *        `tp->total_retrans += segs`). One TSO retransmission of a
     *        3-packet super-segment is THREE packets, so a 2-segment DSACK
     *        is credible; the event counter (1) wrongly rejected it.
     */
    void TestB7B4DsackGateUsesPacketDomain() {
        FsmHarness h;
        h.Warm();
        h.conn.SetSndBuf(1u << 20);
        h.conn.SetTsoTx(true);
        // One 3-packet TSO segment: a single retransmission event, three
        // retransmitted packets.
        h.Send(3 * kMss);
        CHECK(1 == h.conn.RetransQueueSize());
        const UInt32 una = h.conn.SndUna();
        h.now += 3000000;
        h.conn.OnRetransmitTimer(h.now);
        std::fprintf(stderr, "[B7B4] events=%u total_retrans_pkts=%u\n",
                     h.conn.RetransmitCount(), h.conn.TotalRetransPkts());
        CHECK(1 == h.conn.RetransmitCount());
        CHECK(3 == h.conn.TotalRetransPkts());   // red: 0 (field not maintained)
        h.now += 20000;
        h.Deliver(una + 3 * kMss);
        const UInt64 base = h.conn.DeliveredPkts();
        // A 2-segment DSACK: dup_segs = 2 <= total_retrans (3 packets) ->
        // the kernel accepts it. The event count (1) would reject it.
        h.now += 20000;
        h.Deliver(una + 3 * kMss, xtcp::core::kFlagAck, 65535, true,
                  una, una + 2 * kMss);
        std::fprintf(stderr, "[B7B4] delivered %llu -> %llu (expect +2)\n",
                     static_cast<unsigned long long>(base),
                     static_cast<unsigned long long>(h.conn.DeliveredPkts()));
        CHECK(base + 2 == h.conn.DeliveredPkts());   // red: +0 (event gate)
    }
}
int main() {
    xtcp::buf::InitPools();
    xtcp::cc::KccTestSetRandomSeed(2);
    TestKccRegistry();
    TestKccDifferential();
    TestKccRoundBoundaryTracksFlight();
    TestKccRoundBoundaryTracksCurrentRtt();
    TestKccFullBwTransition();
    TestKccG3PathIncreasePerRound();
    TestKccG3PerRoundEvidence();
    TestKccLockRelease();
    TestKccLongPathOutlierDoesNotLock();
    TestKccStickyAndFastFall();
    TestKccSrttGuard();
    TestKccG2PerRound();
    TestKccQdelayBaseline();
    TestKccStalenessDownwardOnly();
    TestKccFullBwThresholdMatchesKernel();
    TestKccProbeCycleAdvances();
    TestKccPacingExtremeClamp();
    TestKccMaxPacingRateClamp();
    TestKccBdpSaturation();
    TestKccPacingUnitGrid();
    TestKccBdpConfirmedBaseline();
    TestKccColdStart();
    TestKccDeliveredRound();
    TestKccDelayedAckFiltered();
    TestKccDelayedAckTruthTable();
    TestKccDrainExit();
    TestKccDrainEdtCredit();
    TestKccCycleRandomized();
    TestKccRandUnbiased();
    TestKccRandRejectionBoundary();
    TestKccSeedUnpredictable();
    TestKccIdleRestart();
    TestKccCwndStartup();
    TestKccCwndLossAndCap();
    TestKccSsthreshPassthroughAndUndo();
    TestKccAppLimitedTruthTable();
    TestKccFsmAppLimitedLostRetransmitted();
    TestKccFsmDelayedFields();
    TestKccFsmTxStartAndAppLimited();
    TestKccFsmCwndStaysLegal();
    TestKccFsmCaStateReturnsToOpen();
    TestNonSackRecoveryHoldsAtHighSeq();
    TestNonSackLossHoldsAtHighSeq();
    TestRtoInRecoveryDoesNotRecut();
    TestNonSackPartialAckRetransmitsNextHole();
    TestKccRecoveryExitKeepsPriorCwnd();
    TestKccRecoveryExitKeepsCcWindow();
    TestExitAckDoesNotBurst();
    TestRecoveryExitCollapsesToSsthresh();
    TestPrrStaysInPackets();
    TestPrrChargesRetransmissions();
    TestNonSackHoldUndoesFirst();
    TestLossExitHasNoCompleteCwr();
    TestApplyCheckpointResetsCongestionView();
    TestApplyCheckpointFullReset();
    TestRepeatedRtoKeepsFirstCut();
    TestRackDoesNotReenterLoss();
    TestRackDoesNotRecutInCwr();
    TestRackKeepsRtoSnapshot();
    TestRackMarksAllOverdueLost();
    TestMigrationResetsKccRecoveryState();
    TestMigrationKeepsRetransTag();
    TestMigrationClearsOooBytes();
    TestKccPipeExcludesLost();
    TestRtoMarksWholeFlightLost();
    TestPipeCountersMatchWalk();
    TestPipeCountersRandomized();
    TestCcInflightExcludesSacked();
    TestKccTxStartOnTlp();
    TestKccDsackCountsDelivered();
    TestKccCycleUsesPriorInflight();
    TestKccFsmTfoRequeue();
    TestKccMigrationEpoch();
    TestKccShortSegPacketDomain();
    TestKccMssMultipleEquivalence();
    TestKccSackDeliveredNoDoubleCount();
    TestKccDifferentialNewFields();
    TestKccRecoveryDifferential();
    TestKccJitterEwmaWideMul();
    TestKccOracleZeroMss();
    TestEifelRejectsNewerTsval();
    TestSpuriousRtoUndoResetsRetransmits();
    TestDsackUndoAfterRtoWithoutTsopt();
    TestNoUndoWhileRetransInFlight();
    TestNoUndoWhenOwnRetransmitCounts();
    TestB7A1AppLimitedCond3Packets();
    TestB7A2MarkerClearedOnEveryAck();
    TestB7A4SackClearsLostOut();
    TestB7B1EmptyDsackIgnored();
    TestB7B2ReversedBlockDoesNotPoisonGate();
    TestDsackDoesNotUndoWithoutMarker();
    TestDsackOfOutOfOrderRecognized();
    TestB7B3OversizedDsackRejected();
    TestB7B4DsackGateUsesPacketDomain();
    xtcp::cc::KccTestResetRandom();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_cc_kcc: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_cc_kcc: all passed\n");
    return 0;
}
