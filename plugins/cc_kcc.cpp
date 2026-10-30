/**
 * @file cc_kcc.cpp
 * @brief KCC v2.0 (Geodesic) port as an XtcpCongestionOps module.
 *
 * Independent C++ implementation of the KCC core (three-component RTT
 * decomposition: T_prop/T_queue/T_noise; geodesic G1/G2/G3 estimator;
 * STARTUP->DRAIN->PROBE_BW FSM). Constants verbatim from ucp_constants.h
 * and tcp_kcc.c. Fidelity-verified against plugins/ref/kcc_core.c.
 */

#include <xtcp/cc/cc.h>

#include "cc_kcc_probe.h"

#include <atomic>
#include <chrono>
#include <new>
#include <random>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {
    using namespace xtcp;
    using namespace xtcp::cc;

    constexpr Int64 kBwUnit = INT64_C(1) << 24;
    constexpr UInt32 kScaleShift = 10;
    constexpr UInt64 kScale = UINT64_C(1) << kScaleShift;

    constexpr UInt32 kG2GrowthNum = 122;
    constexpr UInt32 kG2GrowthDen = 1000;
    constexpr UInt32 kG3FastThNum = 11;
    constexpr UInt32 kG3FastThDen = 10;
    constexpr UInt32 kG3SlowThNum = 21;
    constexpr UInt32 kG3SlowThDen = 20;
    constexpr UInt32 kPdNoiseGateNum = 95;
    constexpr UInt32 kPdNoiseGateDen = 100;
    constexpr UInt32 kJitterSeedShift = 2;
    constexpr UInt32 kJitterEwmaNum = 7;
    constexpr UInt32 kJitterEwmaDen = 8;
    constexpr UInt32 kQdelayEwmaNum = 7;
    constexpr UInt32 kQdelayEwmaDen = 8;
    constexpr UInt32 kMinSamples = 5;
    constexpr UInt32 kStalenessRnds = 128;
    constexpr UInt32 kRttMinFloorUs = 1;
    constexpr UInt32 kRttSampleMaxUs = 500000;
    constexpr UInt32 kPEstInit = 1000;
    constexpr UInt32 kPEstFloor = 10;
    constexpr UInt32 kPEstDecayShift = 4;
    constexpr UInt32 kPEstGrowthShift = 3;
    constexpr UInt32 kPEstMax = 1000000;
    constexpr UInt32 kLockThreshUs = 5000;
    constexpr UInt32 kFastOnlyThreshUs = 7500;
    constexpr UInt32 kBitfield3bitMax = 7;
    constexpr UInt32 kG3FastCnt = 6;
    constexpr UInt32 kG3SlowCnt = 7;
    constexpr UInt32 kMinRttFastFallCnt = 5;
    constexpr UInt32 kMinRttFastFallDiv = 4;
    constexpr UInt32 kMinRttFastFallFastCnt = 2;
    constexpr UInt32 kMinRttStickyNum = 75;
    constexpr UInt32 kMinRttStickyDen = 100;
    constexpr UInt32 kMinRttSrttGuardNum = 90;
    constexpr UInt32 kMinRttSrttGuardDen = 100;
    constexpr UInt32 kSrttSuppressRnds = 24;
    constexpr UInt32 kDefaultRttUs = 1000;
    constexpr UInt64 kFullBwThresh = 320;
    constexpr UInt32 kBwSegMax = 0xFFFFFFFFu;
    constexpr UInt32 kBwRtCycleLen = 10;
    constexpr UInt32 kCycleLen = 8;
    constexpr UInt32 kHighGain = 256 * 2885 / 1000 + 1;   /* BBR_UNIT=256 */
    constexpr UInt32 kCwndGain = 256 * 2;
    constexpr UInt32 kFullBwCnt = 3;
    constexpr UInt32 kCwndMinTarget = 4;
    constexpr UInt32 kCwndAbsoluteMin = 1;
    constexpr UInt32 kCwndProbeBonus = 2;   /* KCC_PROBE_CWND_BONUS (segs) */
    constexpr UInt32 kMinRttUninit = 0xFFFFFFFF;
    constexpr UInt32 kModeStartup = 0;
    constexpr UInt32 kModeProbeBw = 1;
    constexpr UInt32 kModeDrain = 2;

    enum Mode : Byte {
        kStartup = 0,
        kProbeBw = 1,
        kDrain = 2,
    };

    struct BwSample {
        UInt64 val = 0;
        UInt32 rtt_cnt = 0;
    };

    // Test determinism (cc_kcc_probe.h): mode 0 = production per-connection
    // counter, 1 = fixed seed for every connection, 2 = predictable counter.
    std::atomic<UInt32> g_kccConnSeq{0};
    std::atomic<UInt32> g_kccTestSeedMode{0};
    std::atomic<UInt32> g_kccTestSeedValue{0};

    /* SplitMix32: per-connection, deterministic and cheap. */
    UInt32 SplitMix32(UInt32* state) noexcept {
        UInt32 z = (*state += 0x9E3779B9u);
        z = (z ^ (z >> 16)) * 0x21F0AAADu;
        z = (z ^ (z >> 15)) * 0x735A2D97u;
        return z ^ (z >> 15);
    }

    /** @brief Rejection limit for n: 2^32 - (2^32 % n), computed in 64 bits. */
    UInt64 RandLimit(UInt32 n) noexcept {
        const UInt64 range = (UInt64(1) << 32);
        return (0 == n) ? 0 : (range - (range % static_cast<UInt64>(n)));
    }

    /**
     * @brief Single-step rejection test on a raw 32-bit draw.
     * @return True when the draw is inside the unbiased block (out receives
     *         raw % n); false when it must be rejected.
     */
    bool RandBelowFromRaw(UInt64 raw, UInt32 n, UInt32* out) noexcept {
        if (0 == n) {
            if (NULLPTR != out) {
                *out = 0;
            }
            return true;
        }
        if (raw >= RandLimit(n)) {
            return false;
        }
        if (NULLPTR != out) {
            *out = static_cast<UInt32>(raw % static_cast<UInt64>(n));
        }
        return true;
    }

    /**
     * @brief Uniform integer in [0, n) with NO modulo bias.
     *
     * The kernel uses get_random_u32_below()/prandom_u32_max(), both of which
     * reject the biased tail instead of taking a raw modulo. A plain
     * `% n` maps 2^32 values onto n buckets unevenly (the first
     * 2^32 mod n buckets get one extra draw). Rejection sampling discards
     * the incomplete final block, so every bucket is equally likely.
     */
    UInt32 RandBelow(UInt32* state, UInt32 n) noexcept {
        if (0 == n) {
            return 0;
        }
        // Accept only [0, 2^32 - (2^32 % n)): an exact multiple of n.
        // Computing the limit in 64 bits avoids both the 2^32 overflow and
        // the off-by-one of `0xFFFFFFFF - (0xFFFFFFFF % n)` (0xFFFFFFFF is
        // 2^32-1, not 2^32, so that form leaves one extra accepted value).
        // Unbounded rejection loop (kernel style): the accept probability is
        // > 1 - n/2^32, so termination is effectively certain. There is no
        // modulo fallback - that would reintroduce the bias.
        for (;;) {
            UInt32 out = 0;
            if (RandBelowFromRaw(static_cast<UInt64>(SplitMix32(state)), n, &out)) {
                return out;
            }
        }
    }

    /** @brief Cycle counter + OS entropy for seed mixing (rdtsc/steady clock). */
    UInt64 SeedEntropy() noexcept {
#if defined(_MSC_VER)
        const UInt64 cycles = static_cast<UInt64>(__rdtsc());
#elif defined(__x86_64__) || defined(__i386__)
        UInt32 lo = 0;
        UInt32 hi = 0;
        __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
        const UInt64 cycles = (static_cast<UInt64>(hi) << 32) | lo;
#else
        const UInt64 cycles = static_cast<UInt64>(
            std::chrono::steady_clock::now().time_since_epoch().count());
#endif
        // std::random_device is the OS CSPRNG (/dev/urandom,
        // BCryptGenRandom). It is comparatively slow, so it is mixed ONCE per
        // connection with the cheap cycle counter; both feed the SplitMix32
        // seed, so neither a predictable counter progression nor a coarse
        // clock alone determines the phase.
        static std::random_device rd;
        return cycles ^ (static_cast<UInt64>(rd()) << 21);
    }

    UInt32 RandomSeedForConnection() noexcept {
        const UInt32 mode = g_kccTestSeedMode.load(std::memory_order_relaxed);
        if (1 == mode) {
            return g_kccTestSeedValue.load(std::memory_order_relaxed);
        }
        if (2 == mode) {
            // Predictable counter (test-only, deterministic sequencing).
            const UInt32 seq = g_kccTestSeedValue.fetch_add(1, std::memory_order_relaxed) + 1;
            return seq * 2654435761u ^ 0x9E3779B9u;
        }
        const UInt32 seq = g_kccConnSeq.fetch_add(1, std::memory_order_relaxed) + 1;
        // Production seed: entropy ^ cycle counter ^ connection counter.
        // The counter keeps two connections created in the same cycle
        // distinct; the entropy removes the predictable arithmetic
        // progression of a pure counter seed.
        const UInt64 entropy = SeedEntropy();
        UInt32 seed = static_cast<UInt32>(entropy ^ (entropy >> 32));
        seed ^= seq * 2654435761u;
        seed ^= 0x9E3779B9u;
        // A zero state still works for SplitMix32, but keep it nonzero so a
        // snapshot reader can distinguish "seeded" from "untouched".
        return (0 != seed) ? seed : 0xA5A5A5A5u;
    }

    /**
     * @brief KCC private state (per connection, ca_priv).
     */
    struct KccState {
        UInt64  x_est = 0;
        UInt32  p_est = kPEstInit;
        UInt32  qdelay_avg = 0;
        UInt32  jitter_ewma = 0;
        UInt32  sample_cnt = 0;
        UInt32  min_rtt_us = kMinRttUninit;
        UInt32  min_rtt_stamp = 0;
        UInt32  mr_update_rtt_cnt = 0;
        UInt32  rtt_cnt = 0;
        UInt32  confirm_cnt = 0;
        UInt32  confirm_slow_cnt = 0;
        UInt32  locked = 0;
        UInt32  locked_high_cnt = 0;
        UInt32  round_rtt_min = kMinRttUninit;
        UInt32  prev_round_rtt_min = kMinRttUninit;
        UInt32  min_rtt_fast_fall_cnt = 0;
        UInt32  x_est_fall_cnt = 0;
        UInt32  srtt_guard_cnt = 0;
        UInt32  srtt_suppress_cnt = 0;
        BwSample bw_samples[kBwRtCycleLen];
        UInt32  bw_sample_count = 0;
        UInt32  bw_sample_cur = 0;
        UInt64  max_bw = 0;
        UInt32  mode = kModeStartup;
        UInt32  pacing_gain = kHighGain;
        UInt32  cwnd_gain = kHighGain;
        UInt32  cycle_idx = 0;
        UInt64  cycle_mstamp_us = 0;
        UInt32  full_bw_reached = 0;
        UInt64  full_bw = 0;
        UInt32  full_bw_cnt = 0;
        UInt32  has_seen_rtt = 0;
        UInt64  prev_ack_us = 0;
        UInt64  last_ack_us = 0;
        UInt64  total_delivered = 0;
        UInt64  prev_delivered = 0;
        UInt64  next_rtt_delivered = 0;
        UInt64  drain_enter_stamp_us = 0;
        UInt32  idle_restart = 0;
        UInt32  rand_state = 0;     /**< SplitMix32 state (per connection) */
        /**
         * @brief Kernel kcc->prev_ca_state: the CA state seen by the previous
         *        rate sample, used by set_cwnd_to_recover_or_restore.
         */
        Byte    prev_ca_state = 0;
        /** @brief Kernel kcc->packet_conservation (first recovery round). */
        Byte    packet_conservation = 0;
        /** @brief Kernel kcc->prior_cwnd, kept in the CC-private state too. */
        UInt32  prior_cwnd = 0;
        /**
         * @brief ACK-aggregation estimator (Linux tcp_bbr.c
         *        bbr_update_ack_aggregation): max packets ACKed beyond what
         *        max_bw predicts over an ACK epoch, two-slot windowed max.
         */
        UInt64  extra_acked[2] = {0, 0};
        UInt64  ack_epoch_mstamp_us = 0;
        UInt64  ack_epoch_acked = 0;
        Byte    extra_acked_win_rtts = 0;
        Byte    extra_acked_win_idx = 0;

        UInt64 BwMax() const noexcept {
            if (0 == bw_sample_count) {
                return 0;
            }
            UInt64 result = 0;
            for (UInt32 i = 0; i < bw_sample_count; ++i) {
                if (rtt_cnt - bw_samples[i].rtt_cnt >= kBwRtCycleLen) {
                    continue;
                }
                if (bw_samples[i].val > result) {
                    result = bw_samples[i].val;
                }
            }
            if (0 == result) {
                for (UInt32 i = 0; i < bw_sample_count; ++i) {
                    if (bw_samples[i].val > result) {
                        result = bw_samples[i].val;
                    }
                }
            }
            return result;
        }
        void BwUpdate(UInt64 bw, UInt32 cnt_rtt) noexcept {
            if (0 == bw) {
                return;
            }
            // Rate samples can arrive several times within one delivery
            // round. Keep the best sample for that round instead of letting
            // each ACK overwrite one of the ten RTT-window entries.
            if (0 < bw_sample_count && bw_samples[bw_sample_cur].rtt_cnt == cnt_rtt) {
                if (bw > bw_samples[bw_sample_cur].val) {
                    bw_samples[bw_sample_cur].val = bw;
                }
                return;
            }
            if (0 == bw_sample_count) {
                bw_sample_count = 1;
                bw_sample_cur = 0;
                bw_samples[0].val = bw;
                bw_samples[0].rtt_cnt = cnt_rtt;
                return;
            }
            const UInt32 next = (bw_sample_cur + 1) % kBwRtCycleLen;
            bw_samples[next].val = bw;
            bw_samples[next].rtt_cnt = cnt_rtt;
            bw_sample_cur = next;
            if (bw_sample_count < kBwRtCycleLen) {
                ++bw_sample_count;
            }
        }
        UInt32 CycleGain() const noexcept {
            switch (cycle_idx % kCycleLen) {
            case 0: return 256 * 5 / 4;
            case 1: return 256 * 3 / 4;
            default: return 256;
            }
        }
    };

    KccState* Priv(XtcpConnCc* sk) noexcept {
        if (NULLPTR == sk) {
            return NULLPTR;
        }
        if (NULLPTR == sk->ca_priv) {
            sk->ca_priv = new (std::nothrow) KccState();
        }
        return static_cast<KccState*>(sk->ca_priv);
    }

    /* (v * gain) >> 8, decomposed and saturated so it cannot overflow. */
    UInt64 MulShr8(UInt64 v, UInt32 gain) noexcept {
        const UInt64 hi = v >> 8;
        if (0 != gain && hi > (~UInt64(0)) / gain) {
            return ~UInt64(0);
        }
        return hi * gain + (((v & 0xFFu) * gain) >> 8);
    }

    /* (rate * 990000) >> 24: 1% haircut folded with usec->sec. */
    UInt64 HaircutScale(UInt64 rate) noexcept {
        const UInt64 q = rate >> 24;
        const UInt64 r = rate & ((UInt64(1) << 24) - 1);
        return q * 990000ull + ((r * 990000ull) >> 24);
    }

    /**
     * @brief Kernel kcc_bdp in the PACKET domain: ceil(bw * min_rtt *
     *        gain), where bw is segments/usec<<24 (BW_UNIT). Returns
     *        packets, exactly like the kernel's u32 kcc_bdp.
     */
    UInt64 BdpPackets(UInt64 bw, UInt32 min_rtt_us, UInt32 gain) noexcept {
        if (0 == bw || 0 == min_rtt_us) {
            return 0;
        }
        UInt64 product;
        if (bw > (~UInt64(0)) / min_rtt_us) {
            product = ~UInt64(0);
        } else {
            product = bw * min_rtt_us;
        }
        UInt64 bdp = MulShr8(product, gain);
        if (bdp > (~UInt64(0)) - ((UInt64(1) << 24) - 1)) {
            bdp = ~UInt64(0);
        } else {
            bdp += (UInt64(1) << 24) - 1;
        }
        return bdp >> 24;
    }

    /** @brief BdpPackets scaled to bytes (saturating). */
    UInt64 BdpBytes(UInt64 bw, UInt32 min_rtt_us, UInt32 gain, UInt32 mss) noexcept {
        const UInt64 pkts = BdpPackets(bw, min_rtt_us, gain);
        const UInt64 unit = (0 < mss) ? mss : 1460u;
        if (pkts > (~UInt64(0)) / unit) {
            return ~UInt64(0);
        }
        return pkts * unit;
    }

    /**
     * @brief Kernel kcc_quantization_budget (tcp_kcc.c:3859-3864):
     *          cwnd += KCC_TSO_HEADROOM_MULT * kcc_tso_segs_goal(sk);
     *          cwnd  = (cwnd + 1) & ~1U;
     *
     * The DRAIN target and its ssthresh both go through this budget in the
     * kernel (kcc_inflight -> kcc_quantization_budget), so the port's DRAIN
     * gate must use it too; without it the port exits DRAIN one TSO burst
     * too early (audit B6-D2).
     */
    UInt64 QuantizationBudget(UInt64 pkts, UInt32 tso_segs_goal) noexcept {
        const UInt64 with_headroom = pkts + 3ull * tso_segs_goal;
        return (with_headroom + 1ull) & ~UInt64(1);
    }

    /** @brief Kernel kcc_inflight: BDP plus the TSO/quantization headroom. */
    UInt64 BdpInflightPkts(UInt64 bw, UInt32 min_rtt_us, UInt32 gain,
                           UInt32 tso_segs_goal) noexcept {
        return QuantizationBudget(BdpPackets(bw, min_rtt_us, gain), tso_segs_goal);
    }

    /**
     * @brief Kernel kcc_packets_in_net_at_edt: inflight adjusted for the
     *        pacing queue between now and the earliest departure time
     *        (tcp_kcc_c8bead4.c:5016-5037).
     *
     *   interval_us        = (edt_ns - now_ns) / NSEC_PER_USEC
     *   interval_delivered = (bw * interval_us) >> BW_SCALE
     *   inflight_at_edt    = inflight_pkts
     *                        + (pacing_gain > BBR_UNIT ? tso_segs_goal : 0)
     *   if (interval_delivered >= inflight_at_edt) return 0
     *   return inflight_at_edt - interval_delivered
     *
     * The kernel counts PACKETS; xtcp callers compare the result against
     * BdpBytes, so the packet count is scaled back to bytes (mss). `edt_us`
     * is the connection pacing-queue depth: TcpConn::pacing_deadline_ is
     * the equivalent of tp->tcp_wstamp_ns, and both are MICROSECONDS in
     * xtcp (NowUs() is duration_cast<microseconds>; pacing_deadline_ is
     * now + len*1e6/pacing_rate).
     */
    /**
     * @brief Kernel kcc_tso_segs_goal (tcp_kcc.c:3689-3697) for the port's
     *        flat pacing model.
     *
     *   bytes = min(pacing_rate >> pacing_shift, GSO_MAX_SIZE - 1 - MAX_TCP_HEADER)
     *   segs  = max(bytes / mss, min_tso_segs)
     *   segs  = min(segs, KCC_TSO_MAX_SEGS)
     *
     * The port has no sk_pacing_shift / GSO_MAX_SIZE socket fields, so the
     * kernel defaults are pinned here (pacing_shift = 10, i.e. a ~1 ms
     * budget; GSO_MAX_SIZE = 65536; MAX_TCP_HEADER = 120). kcc_min_tso_segs
     * is 1 below KCC_MIN_TSO_RATE/div and 2 above it
     * (tcp_kcc.c:3651-3672), with div halved under high jitter.
     */
    UInt32 TsoSegsGoal(const KccState* k, UInt32 mss, UInt64 pacing_rate) noexcept {
        constexpr UInt64 kGsoMaxSize = 65536;
        constexpr UInt64 kMaxTcpHeader = 120;
        constexpr UInt32 kPacingShift = 10;
        constexpr UInt64 kMinTsoRate = 1200000;
        constexpr UInt32 kMinTsoRateDiv = 8;
        constexpr UInt32 kTsoHighJitterUs = 4000;
        constexpr UInt32 kTsoSegsLow = 1;
        constexpr UInt32 kTsoSegsDefault = 2;
        constexpr UInt32 kTsoMaxSegs = 127;

        UInt32 div = kMinTsoRateDiv;
        if (kTsoHighJitterUs < k->jitter_ewma) {
            div = (1 < (div >> 1)) ? (div >> 1) : 1;
        }
        const UInt64 thresh = (kMinTsoRate / div > 0) ? (kMinTsoRate / div) : 1;
        const UInt32 min_segs =
            (pacing_rate < thresh) ? kTsoSegsLow : kTsoSegsDefault;

        UInt64 bytes = pacing_rate >> kPacingShift;
        const UInt64 cap = kGsoMaxSize - 1 - kMaxTcpHeader;
        if (cap < bytes) {
            bytes = cap;
        }
        if (0 == mss) {
            return min_segs;
        }
        UInt64 segs = bytes / mss;
        if (segs < min_segs) {
            segs = min_segs;
        }
        return (segs > kTsoMaxSegs) ? kTsoMaxSegs : static_cast<UInt32>(segs);
    }

    UInt64 PacketsInNetAtEdt(UInt64 inflight_bytes, UInt32 gain, UInt32 mss,
                             UInt64 bw_pkts, UInt32 edt_us,
                             UInt32 tso_segs_goal) noexcept {
        const UInt64 unit = (0 < mss) ? mss : 1460u;
        UInt64 inflight_pkts = (inflight_bytes + unit - 1) / unit;
        if (gain > 256) {
            // Kernel kcc_packets_in_net_at_edt (tcp_kcc.c:5027-5029):
            //   if (kcc->pacing_gain > BBR_UNIT)
            //       inflight_at_edt += kcc_tso_segs_goal(sk);
            // Not a hardcoded 1: the goal scales with the pacing rate
            // (audit B6-D3).
            inflight_pkts += tso_segs_goal;
        }
        // Kernel: u32 interval_delivered = (u64)kcc_bw(sk) * interval_us
        // >> BW_SCALE - the product is truncated to u32 (audit B6-D4).
        const UInt64 credit64 = (bw_pkts * static_cast<UInt64>(edt_us)) >> 24;
        const UInt32 credit = (credit64 > 0xFFFFFFFFull)
            ? 0xFFFFFFFFu
            : static_cast<UInt32>(credit64);
        if (credit >= inflight_pkts) {
            return 0;
        }
        return (inflight_pkts - credit) * unit;
    }

    void ResetProbeBwMode(KccState* k, UInt64 now_us) noexcept {
        k->mode = kModeProbeBw;
        // Kernel kcc_reset_probe_bw_mode: cycle_idx =
        // CYCLE_LEN-1 - random_below(CYCLE_LEN-1), then advance (&7).
        // The resulting phase is {2,3,4,5,6,7,0} - never 1 (the drain phase
        // must not be the first phase after draining).
        const UInt32 r = RandBelow(&k->rand_state, kCycleLen - 1);
        k->cycle_idx = (kCycleLen - 1) - r;
        k->cycle_idx = (k->cycle_idx + 1) % kCycleLen;
        k->cycle_mstamp_us = now_us;
    }

    /* Shared pacing conversion (kernel kcc_set_pacing_rate). bw is the
     * PACKET-domain estimate (segments/usec << 24). */
    void KccSetPacingRate(KccState* k, XtcpConnCc* sk, UInt64 bw, UInt32 gain) noexcept {
        if (0 == bw) {
            bw = static_cast<UInt64>(kBwUnit);
        }
        // Kernel clamps the estimate to U32_MAX (packets/usec<<24) before
        // converting; the byte rate is then bw * mss.
        if (bw > static_cast<UInt64>(kBwSegMax)) {
            bw = static_cast<UInt64>(kBwSegMax);
        }
        const UInt64 mss = (0 < sk->mss) ? sk->mss : 1460u;
        UInt64 rate = HaircutScale(MulShr8(bw * mss, gain));
        if (0 == k->has_seen_rtt && k->min_rtt_us != kMinRttUninit &&
            0 < k->min_rtt_us && 0 < sk->mss) {
            k->has_seen_rtt = 1;
            const UInt64 rtt = (k->min_rtt_us > 0) ? k->min_rtt_us : 1;
            const UInt64 cwnd_segs = sk->snd_cwnd;
            const UInt64 bdp_bw = (cwnd_segs * kBwUnit) / rtt;
            const UInt64 boot_rate = HaircutScale(
                MulShr8(bdp_bw * sk->mss, kHighGain));
            if (boot_rate > rate) {
                rate = boot_rate;
            }
        }
        if (k->full_bw_reached) {
            sk->pacing_rate = (rate < sk->max_pacing_rate) ? rate : sk->max_pacing_rate;
        } else {
            // Kernel kcc_bw_to_pacing_rate clamps EVERY rate it produces with
            // min_t(u64, rate, sk->sk_max_pacing_rate) (tcp_kcc.c:3563-3567),
            // so a user SO_MAX_PACING_RATE caps the STARTUP ramp and the
            // monotonic gate below compares capped values.
            const UInt64 capped = (rate < sk->max_pacing_rate) ? rate : sk->max_pacing_rate;
            if (capped > sk->pacing_rate) {
                sk->pacing_rate = capped;
            }
        }
    }

    void GeodesicUpdate(KccState* k, UInt32 rtt_us, bool round_start) noexcept {
        const UInt32 rtt = (rtt_us > kRttMinFloorUs) ? rtt_us : kRttMinFloorUs;
        const UInt64 z = static_cast<UInt64>(rtt) << kScaleShift;

        if (0 == k->sample_cnt) {
            k->x_est = z;
            k->p_est = kPEstInit;
            k->qdelay_avg = 0;
            k->jitter_ewma = rtt >> kJitterSeedShift;
            if (k->jitter_ewma < 1) {
                k->jitter_ewma = 1;
            }
            k->sample_cnt = 1;
            return;
        }
        if (1 == k->sample_cnt && k->min_rtt_us != kMinRttUninit && 0 < k->min_rtt_us) {
            const UInt64 ceiling = static_cast<UInt64>(k->min_rtt_us) << kScaleShift;
            if (k->x_est > ceiling) {
                k->x_est = ceiling;
            }
        }

        const Int64 innovation = static_cast<Int64>(z) - static_cast<Int64>(k->x_est);
        const UInt64 abs_innov = (innovation >= 0) ? static_cast<UInt64>(innovation)
                                                   : static_cast<UInt64>(-(innovation + 1)) + 1;

        // G1: instant downward absorption (censored min).
        if (innovation <= 0) {
            k->x_est = (k->x_est < z) ? k->x_est : z;
        } else if (round_start) {
            // G2: bounded geometric growth, once per round, capped at z.
            const UInt64 growth = k->x_est * kG2GrowthNum / kG2GrowthDen;
            UInt64 new_x = k->x_est + growth;
            if (new_x < k->x_est) {
                new_x = 0xFFFFFFFFFFFFFFFFull;
            }
            k->x_est = (new_x < z) ? new_x : z;
        }

        // Staleness: downward-only pull-back to 95% of min_rtt.
        if (k->min_rtt_us != kMinRttUninit &&
            k->rtt_cnt - k->mr_update_rtt_cnt >= kStalenessRnds) {
            const UInt64 mr_scaled = static_cast<UInt64>(k->min_rtt_us) << kScaleShift;
            if (k->x_est <= mr_scaled * kG3FastThNum / kG3FastThDen) {
                const UInt64 target = mr_scaled * kPdNoiseGateNum / kPdNoiseGateDen;
                const UInt64 lowered = (k->x_est < target) ? k->x_est : target;
                k->x_est = (lowered > kScale) ? lowered : kScale;
                k->mr_update_rtt_cnt = k->rtt_cnt;
            }
        }

        // Jitter EWMA (7/8), capped.
        {
            const UInt32 raw_jitter = static_cast<UInt32>(
                (abs_innov >> kScaleShift) > 0xFFFFFFFFull ? 0xFFFFFFFFu
                                                           : static_cast<UInt32>(abs_innov >> kScaleShift));
            k->jitter_ewma = (k->sample_cnt > 1)
                                 ? static_cast<UInt32>(
                                       (static_cast<UInt64>(k->jitter_ewma) * kJitterEwmaNum +
                                        raw_jitter) / kJitterEwmaDen)
                                 : raw_jitter;
            const UInt32 jitter_cap = (k->min_rtt_us != kMinRttUninit)
                                          ? ((k->min_rtt_us > kRttSampleMaxUs) ? k->min_rtt_us : kRttSampleMaxUs)
                                          : kRttSampleMaxUs;
            if (k->jitter_ewma > jitter_cap) {
                k->jitter_ewma = jitter_cap;
            }
        }

        // Queuing-delay EWMA (7/8) against the confirmed min_rtt baseline.
        {
            const UInt64 t_prop_scaled =
                (k->min_rtt_us != kMinRttUninit && 0 < k->min_rtt_us)
                    ? (static_cast<UInt64>(k->min_rtt_us) << kScaleShift)
                    : k->x_est;
            const UInt32 qdelay_instant = (z > t_prop_scaled)
                                              ? static_cast<UInt32>((z - t_prop_scaled) >> kScaleShift)
                                              : 0;
            if (1 == k->sample_cnt) {
                k->qdelay_avg = qdelay_instant;
            } else {
                k->qdelay_avg = static_cast<UInt32>(
                    (static_cast<UInt64>(k->qdelay_avg) * kQdelayEwmaNum + qdelay_instant) / kQdelayEwmaDen);
            }
        }

        if (k->sample_cnt < 0xFFFFFFFFu) {
            ++k->sample_cnt;
        }

        // Convergence proxy p_est.
        if (k->sample_cnt >= kMinSamples) {
            const UInt64 x_est_us = k->x_est >> kScaleShift;
            if (x_est_us <= static_cast<UInt64>(k->min_rtt_us) * kG3SlowThNum / kG3SlowThDen &&
                0 == k->confirm_cnt && 0 == k->confirm_slow_cnt) {
                const UInt32 delta = (k->p_est > kPEstFloor) ? (k->p_est - kPEstFloor) >> kPEstDecayShift : 0;
                if (k->p_est > kPEstFloor + delta) {
                    k->p_est -= (delta > 1) ? delta : 1;
                }
            } else if (x_est_us > static_cast<UInt64>(k->min_rtt_us) * kG3FastThNum / kG3FastThDen) {
                const UInt32 delta = (k->p_est < kPEstInit) ? (kPEstInit - k->p_est) >> kPEstGrowthShift : 0;
                if (k->p_est + delta < kPEstMax) {
                    k->p_est += (delta > 1) ? delta : 1;
                }
            }
        }
    }

    void UpdateMinRtt(KccState* k, UInt32 rtt_us, UInt64 now_us,
                      UInt32 srtt_us, bool round_start) noexcept {
        if (0 == rtt_us) {
            return;
        }
        const UInt32 mr_snapshot = k->min_rtt_us;
        GeodesicUpdate(k, rtt_us, round_start);

        // Cold start: replace the 1ms placeholder with the first real sample.
        if (1 == k->sample_cnt && 0 == k->has_seen_rtt &&
            k->min_rtt_us == kDefaultRttUs) {
            k->min_rtt_us = rtt_us;
        }

        // Lock trigger: a short-path observation with a confirmed short path.
        if (rtt_us < kLockThreshUs && k->min_rtt_us <= kLockThreshUs) {
            k->locked = 1;
        }

        // G3 dual-threshold path-increase detection, once per completed round.
        if (round_start) {
            const UInt32 round_min = k->prev_round_rtt_min;
            if (0 == round_min || kMinRttUninit == round_min) {
                // No usable sample in the previous round: break the chain.
                k->confirm_cnt = 0;
                k->confirm_slow_cnt = 0;
            } else if (0 != k->locked) {
                if (round_min >= kFastOnlyThreshUs) {
                    if (k->locked_high_cnt < kBitfield3bitMax) {
                        ++k->locked_high_cnt;
                    }
                    if (k->locked_high_cnt >= kBitfield3bitMax) {
                        k->locked = 0;
                        k->locked_high_cnt = 0;
                        k->min_rtt_us = round_min;
                        k->min_rtt_stamp = static_cast<UInt32>(now_us);
                        k->srtt_suppress_cnt = kSrttSuppressRnds;
                        k->srtt_guard_cnt = 0;
                    }
                } else {
                    k->locked_high_cnt = 0;
                }
                k->confirm_cnt = 0;
                k->confirm_slow_cnt = 0;
            } else {
                const UInt64 stat = static_cast<UInt64>(round_min) << kScaleShift;
                if (round_min >= kFastOnlyThreshUs) {
                    if (stat >= static_cast<UInt64>(k->min_rtt_us) * kScale *
                                    kG3FastThNum / kG3FastThDen) {
                        if (k->confirm_cnt < kBitfield3bitMax) {
                            ++k->confirm_cnt;
                        }
                    } else {
                        k->confirm_cnt = 0;
                    }
                    if (stat >= static_cast<UInt64>(k->min_rtt_us) * kScale *
                                    kG3SlowThNum / kG3SlowThDen) {
                        if (k->confirm_slow_cnt < kBitfield3bitMax) {
                            ++k->confirm_slow_cnt;
                        }
                    } else {
                        k->confirm_slow_cnt = 0;
                    }
                } else if (round_min >= kLockThreshUs) {
                    // Gray zone (5ms <= round_min < 7.5ms): fast-only.
                    if (stat >= static_cast<UInt64>(k->min_rtt_us) * kScale *
                                    kG3FastThNum / kG3FastThDen) {
                        if (k->confirm_cnt < kBitfield3bitMax) {
                            ++k->confirm_cnt;
                        }
                    } else {
                        k->confirm_cnt = 0;
                    }
                    k->confirm_slow_cnt = 0;
                } else {
                    k->confirm_cnt = 0;
                    k->confirm_slow_cnt = 0;
                }

                // Baseline return: a round at or below min_rtt resets both.
                if (stat <= static_cast<UInt64>(k->min_rtt_us) * kScale) {
                    k->confirm_cnt = 0;
                    k->confirm_slow_cnt = 0;
                }

                if (k->confirm_cnt >= kG3FastCnt || k->confirm_slow_cnt >= kG3SlowCnt) {
                    k->min_rtt_us = round_min;
                    k->min_rtt_stamp = static_cast<UInt32>(now_us);
                    k->confirm_cnt = 0;
                    k->confirm_slow_cnt = 0;
                    k->p_est = kPEstInit;
                    k->mr_update_rtt_cnt = k->rtt_cnt;
                    k->srtt_suppress_cnt = kSrttSuppressRnds;
                    k->srtt_guard_cnt = 0;
                }
            }
        }

        // Traditional min_rtt: no immediate first-sample reduction.
        if (rtt_us <= k->min_rtt_us) {
            const UInt32 r = (rtt_us > kRttMinFloorUs) ? rtt_us : kRttMinFloorUs;
            if (static_cast<UInt64>(r) <
                static_cast<UInt64>(k->min_rtt_us) * kMinRttStickyNum / kMinRttStickyDen) {
                if (round_start) {
                    k->min_rtt_fast_fall_cnt =
                        (k->min_rtt_fast_fall_cnt < kBitfield3bitMax)
                            ? k->min_rtt_fast_fall_cnt + 1
                            : kBitfield3bitMax;
                }
                if (r < k->min_rtt_us / kMinRttFastFallDiv) {
                    if (k->min_rtt_fast_fall_cnt >= kMinRttFastFallFastCnt) {
                        k->min_rtt_us = r;
                        k->min_rtt_fast_fall_cnt = 0;
                    }
                } else if (k->min_rtt_fast_fall_cnt >= kMinRttFastFallCnt) {
                    k->min_rtt_us = r;
                    k->min_rtt_fast_fall_cnt = 0;
                }
            } else {
                k->min_rtt_us = r;
                k->min_rtt_fast_fall_cnt = 0;
            }
            k->min_rtt_stamp = static_cast<UInt32>(now_us);
        } else {
            k->min_rtt_fast_fall_cnt = 0;
        }

        // SRTT guard: sk->srtt_us is unscaled microseconds (no >>3).
        if (0 != k->srtt_suppress_cnt) {
            if (round_start) {
                --k->srtt_suppress_cnt;
            }
            k->srtt_guard_cnt = 0;
        } else if (0 != srtt_us && 0 != k->min_rtt_us) {
            const UInt32 srtt_shifted = (srtt_us > kRttMinFloorUs) ? srtt_us : kRttMinFloorUs;
            if (static_cast<UInt64>(srtt_shifted) <
                static_cast<UInt64>(k->min_rtt_us) * kMinRttSrttGuardNum / kMinRttSrttGuardDen) {
                if (round_start && k->srtt_guard_cnt < kBitfield3bitMax) {
                    ++k->srtt_guard_cnt;
                }
                if (k->srtt_guard_cnt >= kMinRttFastFallCnt) {
                    k->min_rtt_us = srtt_shifted;
                    k->min_rtt_stamp = static_cast<UInt32>(now_us);
                    k->srtt_guard_cnt = 0;
                }
            } else {
                k->srtt_guard_cnt = 0;
            }
        }

        // Downward path-change detection on the completed round's minimum.
        if (round_start && 0 != k->prev_round_rtt_min &&
            kMinRttUninit != k->prev_round_rtt_min) {
            const UInt32 round_min = k->prev_round_rtt_min;
            if (round_min < k->min_rtt_us &&
                static_cast<UInt64>(round_min) <
                    static_cast<UInt64>(k->min_rtt_us) * kPdNoiseGateNum / kPdNoiseGateDen) {
                if (k->x_est_fall_cnt < kMinRttFastFallCnt) {
                    ++k->x_est_fall_cnt;
                }
                if (k->x_est_fall_cnt >= kMinRttFastFallCnt) {
                    k->min_rtt_us = round_min;
                    k->x_est_fall_cnt = 0;
                    k->min_rtt_stamp = static_cast<UInt32>(now_us);
                    k->mr_update_rtt_cnt = k->rtt_cnt;
                }
            } else {
                k->x_est_fall_cnt = 0;
            }
        }

        if (k->min_rtt_us != mr_snapshot) {
            k->mr_update_rtt_cnt = k->rtt_cnt;
        }
    }

    bool IsNextCyclePhase(const KccState* k, const XtcpConnCc* sk,
                          const RateSample* rs, UInt64 now_us) noexcept {
        const UInt64 elapsed = (now_us > k->cycle_mstamp_us)
                                   ? (now_us - k->cycle_mstamp_us)
                                   : 0;
        const bool full_len = elapsed > k->min_rtt_us;
        const UInt32 gain = k->CycleGain();
        if (256 == gain) {
            return full_len;
        }
        // Kernel kcc_is_next_cycle_phase measures rs->prior_in_flight
        // through kcc_packets_in_net_at_edt (pacing-queue adjusted), not the
        // post-ACK sk->inflight.
        // Kernel kcc_is_next_cycle_phase -> kcc_packets_in_net_at_edt with
        // rs->prior_in_flight and the current pacing queue depth.
        const UInt64 inflight = PacketsInNetAtEdt(
            rs->prior_in_flight_bytes, gain, sk->mss, k->max_bw,
            rs->pacing_edt_us, TsoSegsGoal(k, sk->mss, sk->pacing_rate));
        if (gain > 256) {
            const UInt64 target = BdpBytes(k->max_bw, k->min_rtt_us, gain, sk->mss);
            return (full_len && (0 < rs->lost || inflight >= target)) ||
                   (elapsed > static_cast<UInt64>(k->min_rtt_us) * 2);
        }
        const UInt64 target = BdpBytes(k->max_bw, k->min_rtt_us, 256, sk->mss);
        return (full_len && inflight <= target) ||
               (elapsed > static_cast<UInt64>(k->min_rtt_us) * 4);
    }

    // Linux tcp_bbr.c ack-aggregation constants.
    constexpr Byte   kExtraAckedWinRtts = 5;          /* bbr_extra_acked_win_rtts */
    constexpr UInt64 kAckEpochAckedResetThresh = 1u << 20;
    constexpr UInt32 kExtraAckedGain = 256;           /* bbr_extra_acked_gain (BBR_UNIT) */
    constexpr UInt64 kExtraAckedMaxUs = 100u * 1000u; /* bbr_extra_acked_max_us */

    /**
     * @brief Linux bbr_update_ack_aggregation, packet domain.
     *
     * OpenPPP2 delivers the peer's ACKs in batches (one strand drain per
     * GRO/ingress burst), so the ACK clock is aggregated far beyond the
     * min_rtt the BDP is built from. Without this term (and the
     * quantization budget) the KCC v2 cwnd is clamped to
     * cwnd_gain * max_bw * min_rtt - a few packets when min_rtt is tens of
     * microseconds - and throughput collapses to cwnd / (aggregated RTT).
     */
    void UpdateAckAggregation(KccState* k, UInt64 acked, UInt64 now_us,
                              bool round_start, UInt32 snd_cwnd) noexcept {
        if (0 == acked) {
            return;
        }
        if (round_start) {
            if (k->extra_acked_win_rtts < 0x1F) {
                ++k->extra_acked_win_rtts;
            }
            if (k->extra_acked_win_rtts >= kExtraAckedWinRtts) {
                k->extra_acked_win_rtts = 0;
                k->extra_acked_win_idx = k->extra_acked_win_idx ? 0 : 1;
                k->extra_acked[k->extra_acked_win_idx] = 0;
            }
        }
        const UInt64 epoch_us = (now_us > k->ack_epoch_mstamp_us)
            ? (now_us - k->ack_epoch_mstamp_us) : 0;
        UInt64 expected_acked = 0;
        if (0 != k->max_bw && 0 != epoch_us) {
            const UInt64 bw = k->max_bw;
            expected_acked = (epoch_us > (~UInt64(0)) / bw)
                ? (~UInt64(0) >> 24) : ((bw * epoch_us) >> 24);
        }
        if (k->ack_epoch_acked <= expected_acked ||
            k->ack_epoch_acked + acked >= kAckEpochAckedResetThresh) {
            k->ack_epoch_acked = 0;
            k->ack_epoch_mstamp_us = now_us;
            expected_acked = 0;
        }
        k->ack_epoch_acked += acked;
        if (k->ack_epoch_acked > 0xFFFFFu) {
            k->ack_epoch_acked = 0xFFFFFu;
        }
        UInt64 extra = (k->ack_epoch_acked > expected_acked)
            ? (k->ack_epoch_acked - expected_acked) : 0;
        if (extra > snd_cwnd) {
            extra = snd_cwnd;
        }
        if (extra > k->extra_acked[k->extra_acked_win_idx]) {
            k->extra_acked[k->extra_acked_win_idx] = extra;
        }
    }

    /** @brief Linux bbr_ack_aggregation_cwnd, packet domain. */
    UInt64 AckAggregationCwnd(const KccState* k) noexcept {
        if (0 == k->full_bw_reached) {
            return 0;
        }
        const UInt64 max_aggr = (k->max_bw * kExtraAckedMaxUs) >> 24;
        const UInt64 extra = (k->extra_acked[0] > k->extra_acked[1])
            ? k->extra_acked[0] : k->extra_acked[1];
        UInt64 aggr = (kExtraAckedGain * extra) >> 8;
        return (aggr < max_aggr) ? aggr : max_aggr;
    }

    void KccInit(XtcpConnCc* sk) noexcept {
        KccState* k = Priv(sk);
        if (NULLPTR == k) {
            return;
        }
        // Full plugin-epoch reset. Priv() REUSES an existing KccState, so a
        // second init (SetCongestionControl switching algorithms, or a
        // migration ApplyCheckpoint that re-inits the plugin) must not inherit
        // ANY estimator/recovery field from the previous epoch: a stale
        // packet_conservation / prev_ca_state / full_bw / delivered round
        // would keep the new epoch's window frozen (audit A, batch 5).
        k->x_est = 0;
        k->qdelay_avg = 0;
        k->jitter_ewma = 0;
        k->sample_cnt = 0;
        k->min_rtt_stamp = 0;
        k->mr_update_rtt_cnt = 0;
        k->rtt_cnt = 0;
        k->confirm_cnt = 0;
        k->confirm_slow_cnt = 0;
        k->locked = 0;
        k->locked_high_cnt = 0;
        k->round_rtt_min = kMinRttUninit;
        k->prev_round_rtt_min = kMinRttUninit;
        k->min_rtt_fast_fall_cnt = 0;
        k->x_est_fall_cnt = 0;
        k->srtt_guard_cnt = 0;
        k->srtt_suppress_cnt = 0;
        k->bw_sample_count = 0;
        k->bw_sample_cur = 0;
        k->max_bw = 0;
        k->cycle_idx = 0;
        k->cycle_mstamp_us = 0;
        k->full_bw_reached = 0;
        k->full_bw = 0;
        k->full_bw_cnt = 0;
        k->has_seen_rtt = 0;
        k->prev_ack_us = 0;
        k->last_ack_us = 0;
        k->total_delivered = 0;
        k->prev_delivered = 0;
        // Kernel kcc_init recovery interaction (tcp_kcc.c:5490-5510): a new
        // epoch starts in Open with no pending reduction and no saved window.
        k->prev_ca_state = 0;
        k->packet_conservation = 0;
        k->prior_cwnd = 0;
        k->extra_acked[0] = 0;
        k->extra_acked[1] = 0;
        k->ack_epoch_mstamp_us = 0;
        k->ack_epoch_acked = 0;
        k->extra_acked_win_rtts = 0;
        k->extra_acked_win_idx = 0;

        k->mode = kModeStartup;
        k->pacing_gain = kHighGain;
        k->cwnd_gain = kHighGain;
        k->p_est = kPEstInit;
        k->idle_restart = 0;
        k->drain_enter_stamp_us = 0;
        k->next_rtt_delivered = 0;
        k->rand_state = RandomSeedForConnection();
        // Seed the baseline from the connection's existing RTT knowledge.
        // sk->srtt_us is xtcp's unscaled value (kernel uses srtt_us >> 3).
        k->min_rtt_us = (0 < sk->rtt_min_us && kMinRttUninit != sk->rtt_min_us)
                            ? sk->rtt_min_us
                            : ((0 < sk->srtt_us) ? sk->srtt_us : kDefaultRttUs);
        sk->snd_cwnd = 10;                       /* mirror cwnd_segs = 10 */
    }

    void KccRelease(XtcpConnCc* sk) noexcept {
        if (NULLPTR != sk) {
            delete static_cast<KccState*>(sk->ca_priv);
            sk->ca_priv = NULLPTR;
        }
    }

    void KccMain(XtcpConnCc* sk, const RateSample* rs) noexcept {
        KccState* k = Priv(sk);
        if (NULLPTR == k || NULLPTR == rs) {
            return;
        }
        // KCC's whole model is the KERNEL PACKET domain: tp->delivered and
        // rs->delivered count segments (tcp_count_delivered accumulates
        // tcp_skb_pcount). The byte-domain rs->delivered is left untouched
        // for BBR/CUBIC.
        const UInt64 delivered = static_cast<UInt64>(rs->delivered_pkts);
        const UInt32 rtt_us = rs->rtt_us;
        const UInt64 acked = delivered;
        const UInt64 now_us = static_cast<UInt64>(rs->interval_us) + k->last_ack_us;

        k->prev_delivered = k->total_delivered;
        k->total_delivered += acked;
        k->prev_ack_us = k->last_ack_us;
        k->last_ack_us = now_us;

        // ---- 1. Delivered round (kernel kcc_update_bw) ----
        const UInt64 interval_us = (now_us > k->prev_ack_us) ? (now_us - k->prev_ack_us) : 0;
        const bool round_start =
            (0 < rs->interval_us) && (rs->prior_delivered_pkts >= k->next_rtt_delivered);
        if (round_start) {
            k->next_rtt_delivered = rs->delivered_total_pkts;
            k->prev_round_rtt_min = k->round_rtt_min;
            k->round_rtt_min = kMinRttUninit;
            ++k->rtt_cnt;
            k->packet_conservation = 0;
        }
        UInt64 bw = 0;
        if (0 < delivered && 0 < interval_us) {
            bw = (delivered << 24) / interval_us;
            // Kernel clamps the packet-domain estimate to U32_MAX (a plain
            // cast would wrap a multi-terabit value into garbage).
            if (bw > static_cast<UInt64>(kBwSegMax)) {
                bw = static_cast<UInt64>(kBwSegMax);
            }
        }
        // Kernel: app-limited samples may only extend the max when they
        // still reach the running max (tcp_kcc.c:4355).
        if (0 == rs->is_app_limited || bw >= k->BwMax()) {
            k->BwUpdate(bw, k->rtt_cnt);
        }
        k->max_bw = k->BwMax();
        UpdateAckAggregation(k, acked, now_us, round_start, sk->snd_cwnd);

        // ---- 2. PROBE_BW cycle phase (before gains) ----
        if (kModeProbeBw == k->mode && IsNextCyclePhase(k, sk, rs, now_us)) {
            k->cycle_idx = (k->cycle_idx + 1) % kCycleLen;
            k->cycle_mstamp_us = now_us;
        }

        // ---- 3. Full-pipe detection (kernel gate: round_start) ----
        if (0 == k->full_bw_reached && round_start && 0 == rs->is_app_limited) {
            const UInt64 bw_now = k->BwMax();
            // c8bead4: full_bw = 1.25x (320 >> 8). A plateau round grows by
            // less than 25% vs the running max; 3 consecutive plateaus mean
            // STARTUP filled the pipe.
            const UInt64 thresh = (k->full_bw * kFullBwThresh) >> 8;
            if (bw_now >= thresh) {
                k->full_bw = bw_now;
                k->full_bw_cnt = 0;
            } else {
                ++k->full_bw_cnt;
            }
            if (k->full_bw_cnt >= kFullBwCnt) {
                k->full_bw_reached = 1;
            }
        }

        // ---- 4. DRAIN entry/exit (kernel kcc_check_drain) ----
        const UInt32 tso_goal = TsoSegsGoal(k, sk->mss, sk->pacing_rate);
        if (kModeStartup == k->mode && 0 != k->full_bw_reached) {
            k->mode = kModeDrain;
            k->drain_enter_stamp_us = now_us;
            if (0 < sk->mss) {
                // Kernel kcc_check_drain: snd_ssthresh = kcc_inflight(...),
                // i.e. the BDP WITH the quantization budget (audit B6-D2).
                UInt64 segs = BdpInflightPkts(k->max_bw, k->min_rtt_us, 256, tso_goal);
                if (segs > 0x7FFFFFFFull) {
                    segs = 0x7FFFFFFFull;
                }
                sk->snd_ssthresh = static_cast<UInt32>(segs);
            }
        }
        if (kModeDrain == k->mode) {
            // Kernel kcc_check_drain reads the CURRENT tcp_packets_in_flight
            // (kcc_main runs from cong_control, i.e. post-ACK) and adjusts it
            // through kcc_packets_in_net_at_edt.
            const UInt64 inflight =
                PacketsInNetAtEdt(sk->inflight, k->pacing_gain, sk->mss,
                                   k->max_bw, rs->pacing_edt_us, tso_goal);
            // The comparison target is kcc_inflight (BDP + quantization
            // budget), not the bare BDP (audit B6-D2).
            const UInt64 bdp = BdpInflightPkts(k->max_bw, k->min_rtt_us, 256, tso_goal) *
                               ((0 < sk->mss) ? sk->mss : 1460u);
            const UInt64 elapsed = (now_us > k->drain_enter_stamp_us)
                ? (now_us - k->drain_enter_stamp_us) : 0;
            const UInt64 min_rtt = (kMinRttUninit == k->min_rtt_us) ? 0 : k->min_rtt_us;
            const bool drained = inflight <= bdp;
            const bool one_rtt = elapsed > min_rtt;
            const bool timeout = elapsed > min_rtt * 4;
            if ((drained && one_rtt) || timeout) {
                ResetProbeBwMode(k, now_us);
            }
        }

        // ---- 5. min_rtt, then delayed-ACK-gated round_rtt_min ----
        if (0 < rtt_us) {
            UpdateMinRtt(k, rtt_us, now_us, sk->srtt_us, round_start);
            if (!rs->is_ack_delayed && rtt_us < k->round_rtt_min) {
                k->round_rtt_min = rtt_us;
            }
        }
        // Kernel clears idle_restart once the connection delivers again.
        if (0 < delivered) {
            k->idle_restart = 0;
        }

        // ---- 6. Gains ----
        switch (k->mode) {
        case kModeStartup:
            k->pacing_gain = kHighGain;
            k->cwnd_gain = kHighGain;
            break;
        case kModeDrain:
            k->pacing_gain = 256 * 1000 / 2885;
            k->cwnd_gain = kHighGain;
            break;
        case kModeProbeBw:
            k->pacing_gain = k->CycleGain();
            k->cwnd_gain = kCwndGain;
            break;
        }

        // ---- Outputs ----
        const UInt64 pacing_bw = (0 != k->max_bw) ? k->max_bw
            : ((0 != bw) ? bw : static_cast<UInt64>(kBwUnit));
        KccSetPacingRate(k, sk, pacing_bw, k->pacing_gain);

        // Kernel kcc_set_cwnd opens with kcc_set_cwnd_to_recover_or_restore:
        //   losses                     -> cwnd -= losses
        //   Open -> Recovery (first)   -> packet_conservation = 1,
        //                                 next_rtt_delivered = delivered,
        //                                 cwnd = inflight + acked
        //   Recovery -> Open           -> cwnd = max(cwnd, prior_cwnd)
        // While packet_conservation is set the sample sends only what was
        // acknowledged (no additive growth this round).
        const UInt64 mss = (0 < sk->mss) ? sk->mss : 1460u;
        const Byte prev_state = k->prev_ca_state;
        const Byte ca_state = sk->ca_state;
        UInt64 cwnd_pkts = sk->snd_cwnd;
        bool conserve = false;
        if (0 < acked) {
            // Kernel kcc_set_cwnd (tcp_kcc.c:3992-3998):
            //   if (rs->losses > 0) cwnd -= rs->losses;
            // rs->losses is the PACKET count of freshly lost segments
            // (tcp_input_66.c:3936), so the port must not round a byte total
            // up here - a 2*MSS loss and a 1-byte loss are 2 vs 1 packets.
            if (0 < rs->lost_pkts) {
                const UInt64 lost_pkts = static_cast<UInt64>(rs->lost_pkts);
                cwnd_pkts = (cwnd_pkts > lost_pkts)
                    ? cwnd_pkts - lost_pkts
                    : static_cast<UInt64>(kCwndAbsoluteMin);
            }
            if (3 == ca_state && 3 != prev_state) {
                k->packet_conservation = 1;
                k->next_rtt_delivered = rs->delivered_total_pkts;
                const UInt64 inflight_pkts =
                    (static_cast<UInt64>(sk->inflight) + mss - 1) / mss;
                cwnd_pkts = inflight_pkts + acked;
            } else if (3 <= prev_state && 3 > ca_state) {
                if (sk->prior_cwnd > cwnd_pkts) {
                    cwnd_pkts = sk->prior_cwnd;
                }
                k->packet_conservation = 0;
            }
            if (ca_state != prev_state) {
                k->prev_ca_state = ca_state;
            }
            if (0 != k->packet_conservation) {
                const UInt64 inflight_pkts =
                    (static_cast<UInt64>(sk->inflight) + mss - 1) / mss;
                const UInt64 floor_cwnd = inflight_pkts + acked;
                if (floor_cwnd > cwnd_pkts) {
                    cwnd_pkts = floor_cwnd;
                }
                conserve = true;
            }
        }
        if (!conserve && 0 < acked) {
            if (k->min_rtt_us != kMinRttUninit && 0 < k->min_rtt_us) {
                // Raw max_bw (only the pacing path floors to BW_UNIT).
                // Linux bbr_set_cwnd: target = bdp + ack_aggregation_cwnd,
                // then bbr_quantization_budget (TSO headroom). KCC v2 kept
                // only the bare BDP here (it already uses the quantization
                // budget for the DRAIN gate), which pins cwnd at a handful
                // of packets on a tiny-min_rtt path whose ACKs are batched.
                UInt64 target = BdpPackets(k->max_bw, k->min_rtt_us, k->cwnd_gain);
                target += AckAggregationCwnd(k);
                target = QuantizationBudget(
                    target, TsoSegsGoal(k, sk->mss, sk->pacing_rate));
                if (kModeProbeBw == k->mode && 0 == k->cycle_idx) {
                    target += kCwndProbeBonus;
                }
                if (0 != k->full_bw_reached) {
                    UInt64 grown = cwnd_pkts + acked;
                    if (grown < cwnd_pkts) {
                        grown = ~UInt64(0);
                    }
                    cwnd_pkts = (grown < target) ? grown : target;
                } else if (cwnd_pkts < target || rs->delivered_total_pkts < 10ull) {
                    UInt64 grown = cwnd_pkts + acked;
                    if (grown < cwnd_pkts) {
                        grown = ~UInt64(0);
                    }
                    cwnd_pkts = grown;
                }
            }
        }
        if (cwnd_pkts < static_cast<UInt64>(kCwndMinTarget)) {
            cwnd_pkts = kCwndMinTarget;
        }
        sk->snd_cwnd = (cwnd_pkts > 0x7FFFFFFFull)
            ? 0x7FFFFFFFu
            : static_cast<UInt32>(cwnd_pkts);
    }

    void KccCwndEvent(XtcpConnCc* sk, CaEvent ev) noexcept {
        if (kCaEventTxStart != ev || NULLPTR == sk) {
            return;
        }
        KccState* k = Priv(sk);
        if (NULLPTR == k || 0 == sk->app_limited) {
            return;
        }
        k->idle_restart = 1;
        if (kModeProbeBw == k->mode) {
            // Restart the phase clock from the last delivery time (kernel
            // tp->delivered_mstamp) and re-anchor pacing at 1.0x.
            k->cycle_mstamp_us = k->last_ack_us;
            KccSetPacingRate(k, sk, (0 != k->max_bw) ? k->max_bw
                                                     : static_cast<UInt64>(kBwUnit),
                             256);
        }
    }

    /**
     * @brief Kernel kcc_ssthresh: save the current window for a later undo
     *        and PASS THE CURRENT ssthresh THROUGH (the kernel never lowers
     *        snd_ssthresh here; tcp_enter_loss assigns the return value).
     *        The window cut itself is the FSM's job (cwnd = inflight + 1).
     */
    UInt32 KccSsthresh(XtcpConnCc* sk) noexcept {
        if (NULLPTR == sk) {
            return 0;
        }
        // Kernel kcc_save_cwnd: entering a recovery keeps the pre-recovery
        // peak (a second save inside recovery must not shrink it).
        if (sk->ca_state < 3) {
            sk->prior_cwnd = sk->snd_cwnd;
        } else if (sk->snd_cwnd > sk->prior_cwnd) {
            sk->prior_cwnd = sk->snd_cwnd;
        }
        return sk->snd_ssthresh;
    }

    /**
     * @brief Kernel kcc_undo_cwnd: a spurious-loss verdict restores the
     *        saved window and resets the full-pipe detection so STARTUP can
     *        re-probe the (larger) capacity.
     */
    UInt32 KccUndoCwnd(XtcpConnCc* sk) noexcept {
        if (NULLPTR == sk) {
            return 0;
        }
        KccState* k = Priv(sk);
        if (NULLPTR != k) {
            k->full_bw = 0;
            k->full_bw_cnt = 0;
        }
        return sk->snd_cwnd;
    }

    /**
     * @brief Kernel kcc_set_state (tcp_kcc.c:5657-5667): entering CA_Loss
     *        invalidates the full-pipe verdict AND records the state so
     *        kcc_set_cwnd_to_recover_or_restore can later see the
     *        Loss -> Open transition and restore prior_cwnd.
     */
    void KccSetState(XtcpConnCc* sk, Byte new_state) noexcept {
        if (NULLPTR == sk || 4 != new_state) {
            return;
        }
        KccState* k = Priv(sk);
        if (NULLPTR != k) {
            // Kernel kcc->prev_ca_state = TCP_CA_Loss. WITHOUT this write the
            // port's kcc_set_cwnd_to_recover_or_restore never observes
            // `prev_state >= Recovery && state < Recovery` after a loss episode
            // (cc_kcc.cpp:957), so KCC never runs the kernel's Loss->Open
            // bookkeeping: packet_conservation is left set and the window is
            // never restored to prior_cwnd at the episode exit. Measured on a
            // REAL loss (probe34, real handshake, Eifel correctly rejecting the
            // undo): KCC exits the episode at cwnd 4 -> 14 by BDP re-growth
            // while Reno exits at 2 -> 5 (audit D07).
            k->prev_ca_state = 4;   // TCP_CA_Loss
            // Kernel also sets round_start = 1 and runs
            // kcc_lt_bw_sampling(sk, {.losses = 1}); the port has no LT-BW
            // sampler, so only the round boundary is mirrored: a loss starts a
            // new delivered round, exactly like kcc_update_bw's round_start.
            k->next_rtt_delivered = 0;
            k->full_bw = 0;
            k->full_bw_cnt = 0;
        }
    }

    const XtcpCongestionOps& KccOps() noexcept {
        static const XtcpCongestionOps ops = {
            "kcc",
            KccInit,
            KccRelease,
            KccSsthresh,
            NULLPTR,          /* cong_avoid */
            KccSetState,      /* set_state (CA_Loss -> full_bw = 0) */
            KccCwndEvent,     /* cwnd_event (kCaEventTxStart idle restart) */
            NULLPTR,          /* pkts_acked */
            KccUndoCwnd,      /* undo_cwnd (clear full_bw, keep cwnd) */
            KccMain,          /* cong_control */
            NULLPTR,
            0,
        };
        return ops;
    }
}

namespace xtcp {
    namespace cc {
        bool KccGetSnapshot(const XtcpConnCc* sk, KccSnapshot* out) noexcept {
            if (NULLPTR == sk || NULLPTR == out || NULLPTR == sk->ca_priv) {
                return false;
            }
            const KccState* k = static_cast<const KccState*>(sk->ca_priv);
            KccSnapshot snapshot;
            snapshot.x_est = k->x_est;
            snapshot.max_bw = k->max_bw;
            snapshot.full_bw = k->full_bw;
            snapshot.p_est = k->p_est;
            snapshot.qdelay_avg = k->qdelay_avg;
            snapshot.jitter_ewma = k->jitter_ewma;
            snapshot.sample_cnt = k->sample_cnt;
            snapshot.min_rtt_us = k->min_rtt_us;
            snapshot.rtt_cnt = k->rtt_cnt;
            snapshot.confirm_cnt = k->confirm_cnt;
            snapshot.confirm_slow_cnt = k->confirm_slow_cnt;
            snapshot.locked = k->locked;
            snapshot.locked_high_cnt = k->locked_high_cnt;
            snapshot.min_rtt_fast_fall_cnt = k->min_rtt_fast_fall_cnt;
            snapshot.x_est_fall_cnt = k->x_est_fall_cnt;
            snapshot.srtt_guard_cnt = k->srtt_guard_cnt;
            snapshot.srtt_suppress_cnt = k->srtt_suppress_cnt;
            snapshot.round_rtt_min = k->round_rtt_min;
            snapshot.prev_round_rtt_min = k->prev_round_rtt_min;
            snapshot.mode = k->mode;
            snapshot.pacing_gain = k->pacing_gain;
            snapshot.cwnd_gain = k->cwnd_gain;
            snapshot.cycle_idx = k->cycle_idx;
            snapshot.full_bw_reached = k->full_bw_reached;
            snapshot.full_bw_cnt = k->full_bw_cnt;
            snapshot.has_seen_rtt = k->has_seen_rtt;
            snapshot.next_rtt_delivered = k->next_rtt_delivered;
            snapshot.total_delivered = k->total_delivered;
            snapshot.cycle_mstamp_us = k->cycle_mstamp_us;
            snapshot.last_ack_us = k->last_ack_us;
            snapshot.drain_enter_stamp_us = k->drain_enter_stamp_us;
            snapshot.idle_restart = k->idle_restart;
            snapshot.rand_state = k->rand_state;
            snapshot.ca_state = sk->ca_state;
            snapshot.prev_ca_state = k->prev_ca_state;
            snapshot.prior_cwnd = sk->prior_cwnd;
            snapshot.packet_conservation = k->packet_conservation;
            *out = snapshot;
            return true;
        }

        void KccTestSetRandomSeed(UInt32 seed) noexcept {
            g_kccTestSeedMode.store(1, std::memory_order_relaxed);
            g_kccTestSeedValue.store(seed, std::memory_order_relaxed);
        }

        void KccTestSetRandomCounter(UInt32 counter) noexcept {
            g_kccTestSeedMode.store(2, std::memory_order_relaxed);
            g_kccTestSeedValue.store(counter, std::memory_order_relaxed);
        }

        void KccTestResetRandom() noexcept {
            g_kccTestSeedMode.store(0, std::memory_order_relaxed);
            g_kccTestSeedValue.store(0, std::memory_order_relaxed);
        }

        UInt32 KccTestRandBelow(UInt32* state, UInt32 n) noexcept {
            if (NULLPTR == state) {
                return 0;
            }
            return RandBelow(state, n);
        }

        UInt64 KccTestRandLimit(UInt32 n) noexcept {
            return RandLimit(n);
        }

        bool KccTestRandBelowFromRaw(UInt64 raw, UInt32 n, UInt32* out) noexcept {
            return RandBelowFromRaw(raw, n, out);
        }

        UInt32 KccTestIsNextCyclePhase(XtcpConnCc* sk, const RateSample* rs,
                                       UInt64 now_us) noexcept {
            if (NULLPTR == sk || NULLPTR == rs) {
                return 0;
            }
            const KccState* k = Priv(sk);
            if (NULLPTR == k) {
                return 0;
            }
            return IsNextCyclePhase(k, sk, rs, now_us) ? 1u : 0u;
        }

        UInt32 KccTestTsoSegsGoal(XtcpConnCc* sk) noexcept {
            if (NULLPTR == sk) {
                return 1;
            }
            const KccState* k = Priv(sk);
            if (NULLPTR == k) {
                return 1;
            }
            return TsoSegsGoal(k, sk->mss, sk->pacing_rate);
        }

        UInt64 KccTestPacketsInNetAtEdt(UInt64 inflight_bytes, UInt32 gain, UInt32 mss,
                                        UInt64 bw_pkts, UInt32 edt_us,
                                        UInt32 tso_segs_goal) noexcept {
            return PacketsInNetAtEdt(inflight_bytes, gain, mss, bw_pkts, edt_us,
                                     tso_segs_goal);
        }

        /**
         * @brief Registers the KCC port (KCC is the stack's default CC; select
         *        others via SetDefaultCongestionControl; built-in Reno remains
         *        the fallback when no plugin is configured).
         */
        void RegisterKcc() noexcept {
            RegisterCongestionControl(KccOps());
        }
    }
}