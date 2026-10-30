/*
 * kcc_core.c
 *
 * KCC v2.0 (Geodesic) pure computation core extracted from the UCP
 * userspace port, which mirrors
 * the kernel tcp_kcc.c algorithm. Reference for fidelity differential
 * testing. Constants are verbatim from ucp_constants.h / tcp_kcc.c.
 *
 * Synced to c8bead4: per-round G2/G3 evidence, min_rtt lock/confirmation,
 * SRTT guard, PROBE_BW cycle phase, 1.25x full-bw detection and overflow-safe
 * pacing conversion. Only the portable subset is modelled (no LT-BW/KF/ECN/
 * TSO/ACK-aggregation/recovery).
 */

#if defined(__GNUC__) || defined(__clang__)
#define XTCP_KCC_UNUSED __attribute__((unused))
#else
#define XTCP_KCC_UNUSED
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4505)
#endif

#include <stdint.h>
#include <string.h>

#define BW_SCALE 24
#define BW_UNIT (INT64_C(1) << BW_SCALE)
#define BBR_SCALE 8
#define BBR_UNIT (1 << BBR_SCALE)
#define KCC_SCALE_SHIFT 10
#define KCC_SCALE (INT64_C(1) << KCC_SCALE_SHIFT)

#define KCC_G2_GROWTH_NUM 122
#define KCC_G2_GROWTH_DEN 1000
#define KCC_G3_FAST_TH_NUM 11
#define KCC_G3_FAST_TH_DEN 10
#define KCC_G3_SLOW_TH_NUM 21
#define KCC_G3_SLOW_TH_DEN 20
#define KCC_G3_FAST_CNT 6
#define KCC_G3_SLOW_CNT 7
#define KCC_PD_NOISE_GATE_NUM 95
#define KCC_PD_NOISE_GATE_DEN 100
#define KCC_JITTER_SEED_SHIFT 2
#define KCC_EWMA_JITTER_NUM 7
#define KCC_EWMA_JITTER_DEN 8
#define KCC_EWMA_QDELAY_NUM 7
#define KCC_EWMA_QDELAY_DEN 8
#define KCC_MIN_SAMPLES 5
#define KCC_STALENESS_RNDS 128
#define KCC_RTT_MIN_FLOOR_US 1
#define KCC_RTT_SAMPLE_MAX_US 500000
#define KCC_P_EST_INIT 1000
#define KCC_P_EST_FLOOR 10
#define KCC_P_EST_DECAY_SHIFT 4
#define KCC_P_EST_GROWTH_SHIFT 3
#define KCC_P_EST_MAX 1000000
#define KCC_LOCK_THRESH_US 5000
#define KCC_FAST_ONLY_THRESH_US 7500
#define KCC_BITFIELD_3BIT_MAX 7
#define KCC_MINRTT_FAST_FALL_CNT 5
#define KCC_MINRTT_FAST_FALL_DIV 4
#define KCC_MINRTT_FAST_FALL_FAST_CNT 2
#define KCC_MINRTT_STICKY_NUM 75
#define KCC_MINRTT_STICKY_DEN 100
#define KCC_MINRTT_SRTT_GUARD_NUM 90
#define KCC_MINRTT_SRTT_GUARD_DEN 100
#define KCC_SRTT_SUPPRESS_RNDS 24
#define KCC_BW_RT_CYCLE_LEN 10
#define KCC_PROBE_BW_CYCLE_LEN 8
#define KCC_HIGH_GAIN (BBR_UNIT * 2885 / 1000 + 1)
#define KCC_DRAIN_GAIN (BBR_UNIT * 1000 / 2885)
#define KCC_CWND_GAIN (BBR_UNIT * 2)
#define KCC_FULL_BW_THRESH 320
#define KCC_FULL_BW_CNT 3
#define KCC_CWND_MIN_TARGET 4
#define KCC_CWND_ABSOLUTE_MIN 1
#define KCC_BW_SEG_MAX 0xFFFFFFFFu
#define KCC_DEFAULT_RTT_US 1000
#define MICROS_PER_SECOND 1000000LL
#define MIN_RTT_UNINIT 0xFFFFFFFFu

/* Kernel TSO headroom constants (tcp_kcc.c:3035-3069). */
#define KCC_MIN_TSO_RATE 1200000
#define KCC_MIN_TSO_RATE_DIV 8
#define KCC_TSO_HEADROOM_MULT 3
#define KCC_TSO_MAX_SEGS 127
#define KCC_TSO_SEGS_LOW 1
#define KCC_TSO_SEGS_DEFAULT 2
#define KCC_TSO_HIGH_JITTER_THRESH_US 4000
#define KCC_TSO_DIV_HALVE_SHIFT 1

#define KCC_MODE_STARTUP 0
#define KCC_MODE_PROBE_BW 1
#define KCC_MODE_DRAIN 2

#define GAIN_PROBE_PHASE_NUM 5
#define GAIN_PROBE_PHASE_DEN 4
#define GAIN_DRAIN_PHASE_NUM 3
#define GAIN_DRAIN_PHASE_DEN 4
#define GAIN_CRUISE_PHASE_NUM 1
#define GAIN_CRUISE_PHASE_DEN 1

typedef int64_t s64;
typedef uint64_t u64;
typedef int32_t s32;
typedef uint32_t u32;
typedef uint8_t u8;

struct kcc_bw_sample {
	s64 val;
	u32 rtt_cnt;
};

struct kcc_core {
	/* Geodesic estimator state */
	u64  x_est;            /* scaled by KCC_SCALE */
	u32  p_est;
	u32  qdelay_avg;
	u32  jitter_ewma;
	u32  sample_cnt;
	u32  min_rtt_us;
	u32  min_rtt_stamp;
	u32  mr_update_rtt_cnt;
	u32  rtt_cnt;
	u32  confirm_cnt;
	u32  confirm_slow_cnt;
	u32  locked;
	u32  locked_high_cnt;
	u32  min_rtt_fast_fall_cnt;
	u32  x_est_fall_cnt;
	u32  srtt_guard_cnt;
	u32  srtt_suppress_cnt;

	/* Per-round RTT statistics */
	u32  round_rtt_min;
	u32  prev_round_rtt_min;

	/* Bandwidth window */
	struct kcc_bw_sample bw_samples[KCC_BW_RT_CYCLE_LEN];
	u32  bw_sample_count;
	u32  bw_sample_cur;
	s64  max_bw;

	/* FSM */
	u32  mode;
	u32  snd_ssthresh;
	u32  pacing_gain;
	u32  cwnd_gain;
	u32  cycle_idx;
	u64  cycle_mstamp_us;
	u32  full_bw_reached;
	u64  full_bw;
	u32  full_bw_cnt;
	u32  has_seen_rtt;
	u64  prev_ack_us;
	u64  last_ack_us;
	s64  total_delivered;
	s64  prev_delivered;
	s64  next_rtt_delivered;
	u64  drain_enter_stamp_us;
	u32  idle_restart;
	u32  rand_state;

	/* Inputs */
	u32  mss;
	u32  srtt_us;          /* smoothed RTT in real microseconds (xtcp scale) */
	s64  congestion_window_bytes;
	u32  flight_bytes;
	/* Recovery interaction (kernel icsk_ca_state /
	 * kcc_set_cwnd_to_recover_or_restore). */
	u32  ca_state;             /* 0=Open, 3=Recovery, 4=Loss */
	u32  prev_ca_state;
	u32  prior_cwnd;
	u32  packet_conservation;
	/* Linux tcp_bbr.c ack-aggregation estimator (packet domain). */
	u64  extra_acked[2];
	u64  ack_epoch_mstamp_us;
	u64  ack_epoch_acked;
	u32  extra_acked_win_rtts;
	u32  extra_acked_win_idx;

	/* Kernel sk->sk_max_pacing_rate: the ceiling kcc_bw_to_pacing_rate
	 * applies to every rate it produces (tcp_kcc.c:3563-3567). ~0 = none,
	 * matching the kernel default. */
	u64  max_pacing_rate;

	/* Outputs */
	s64  pacing_rate_bytes_per_second;
	s64  cwnd_segs;
};

/* Read-only snapshot for field-by-field differential testing. */
struct kcc_snapshot {
	u64 x_est;
	u64 max_bw;
	u64 full_bw;
	u32 p_est;
	u32 qdelay_avg;
	u32 jitter_ewma;
	u32 sample_cnt;
	u32 min_rtt_us;
	u32 rtt_cnt;
	u32 confirm_cnt;
	u32 confirm_slow_cnt;
	u32 locked;
	u32 locked_high_cnt;
	u32 min_rtt_fast_fall_cnt;
	u32 x_est_fall_cnt;
	u32 srtt_guard_cnt;
	u32 srtt_suppress_cnt;
	u32 round_rtt_min;
	u32 prev_round_rtt_min;
	u32 mode;
	u32 pacing_gain;
	u32 cwnd_gain;
	u32 cycle_idx;
	u32 full_bw_reached;
	u32 full_bw_cnt;
	u32 has_seen_rtt;
	u32 idle_restart;
	u64 next_rtt_delivered;
	u64 total_delivered;
	u64 cycle_mstamp_us;
	u64 last_ack_us;
	u64 drain_enter_stamp_us;
	u32 rand_state;
	u32 ca_state;
	u32 prev_ca_state;
	u32 prior_cwnd;
	u32 packet_conservation;
};

static u64 kcc_min_u64(u64 a, u64 b) { return a < b ? a : b; }

/* Linux bbr_update_ack_aggregation / bbr_ack_aggregation_cwnd in the packet
 * domain; mirrors the C++ port's UpdateAckAggregation/AckAggregationCwnd. */
static void kcc_update_ack_aggregation(struct kcc_core *k, u64 acked, u64 now_us,
				       int round_start) {
	u64 epoch_us;
	u64 expected_acked = 0;
	u64 extra;

	if (acked == 0) return;
	if (round_start) {
		if (k->extra_acked_win_rtts < 0x1F) k->extra_acked_win_rtts++;
		if (k->extra_acked_win_rtts >= 5) {
			k->extra_acked_win_rtts = 0;
			k->extra_acked_win_idx = k->extra_acked_win_idx ? 0 : 1;
			k->extra_acked[k->extra_acked_win_idx] = 0;
		}
	}
	epoch_us = (now_us > k->ack_epoch_mstamp_us) ? now_us - k->ack_epoch_mstamp_us : 0;
	if (k->max_bw != 0 && epoch_us != 0) {
		u64 bw = (u64)k->max_bw;
		expected_acked = (epoch_us > (~(u64)0) / bw)
			? ((~(u64)0) >> 24) : ((bw * epoch_us) >> 24);
	}
	if (k->ack_epoch_acked <= expected_acked ||
	    k->ack_epoch_acked + acked >= (1u << 20)) {
		k->ack_epoch_acked = 0;
		k->ack_epoch_mstamp_us = now_us;
		expected_acked = 0;
	}
	k->ack_epoch_acked += acked;
	if (k->ack_epoch_acked > 0xFFFFFu) k->ack_epoch_acked = 0xFFFFFu;
	extra = (k->ack_epoch_acked > expected_acked) ? k->ack_epoch_acked - expected_acked : 0;
	if (extra > (u64)k->cwnd_segs) extra = (u64)k->cwnd_segs;
	if (extra > k->extra_acked[k->extra_acked_win_idx])
		k->extra_acked[k->extra_acked_win_idx] = extra;
}

static u64 kcc_ack_aggregation_cwnd(const struct kcc_core *k) {
	u64 max_aggr;
	u64 extra;
	if (!k->full_bw_reached) return 0;
	max_aggr = ((u64)k->max_bw * 100000ull) >> 24;
	extra = k->extra_acked[0] > k->extra_acked[1] ? k->extra_acked[0] : k->extra_acked[1];
	extra = (256ull * extra) >> 8;
	return extra < max_aggr ? extra : max_aggr;
}
static u32 kcc_max_u32(u32 a, u32 b) { return a > b ? a : b; }

/* SplitMix32: must match the port exactly for the differential oracle. */
static u32 kcc_splitmix32(u32 *state) {
	u32 z = (*state += 0x9E3779B9u);
	z = (z ^ (z >> 16)) * 0x21F0AAADu;
	z = (z ^ (z >> 15)) * 0x735A2D97u;
	return z ^ (z >> 15);
}

/* Uniform [0, n) with NO modulo bias: rejection sampling, mirroring the
 * port (and the kernel's get_random_u32_below/prandom_u32_max, which reject
 * the incomplete tail instead of taking a raw modulo). */
static u32 kcc_rand_below(u32 *state, u32 n) {
	u64 range;
	u64 limit;
	if (n == 0) return 0;
	/* Accept only [0, 2^32 - (2^32 % n)) - an exact multiple of n. The
	 * limit MUST be computed in 64 bits: 0xFFFFFFFF is 2^32-1, so the naive
	 * u32 form leaves one extra accepted value (off-by-one bias). The loop
	 * is unbounded like the kernel's get_random_u32_below(); there is no
	 * modulo fallback (that would reintroduce the bias). */
	range = (u64)1 << 32;
	limit = range - (range % (u64)n);
	for (;;) {
		u64 r = (u64)kcc_splitmix32(state);
		if (r < limit) return (u32)(r % (u64)n);
	}
}

/* (v * gain) >> BBR_SCALE, decomposed and saturated so it cannot overflow. */
static u64 kcc_mul_shr8(u64 v, u32 gain) {
	u64 hi = v >> BBR_SCALE;
	if (gain != 0 && hi > (~(u64)0) / gain) {
		return ~(u64)0;
	}
	return hi * gain + (((v & 0xFFu) * gain) >> BBR_SCALE);
}

/* (rate * 990000) >> BW_SCALE (1% haircut folded with usec->sec). */
static u64 kcc_haircut_scale(u64 rate) {
	u64 q = rate >> BW_SCALE;
	u64 r = rate & (u64)(BW_UNIT - 1);
	return q * 990000ULL + ((r * 990000ULL) >> BW_SCALE);
}

/* Packet-domain BDP (kernel kcc_bdp): ceil(bw * min_rtt * gain), where bw is
 * segments/usec << BW_SCALE. The result is PACKETS, like the kernel's u32. */
static u64 kcc_bdp_packets(u64 bw, u32 min_rtt_us, u32 gain) {
	u64 product;
	if (0 == bw || 0 == min_rtt_us) return 0;
	if (bw > (~(u64)0) / min_rtt_us) {
		product = ~(u64)0;
	} else {
		product = bw * min_rtt_us;
	}
	{
		u64 bdp = kcc_mul_shr8(product, gain);
		if (bdp > (~(u64)0) - (u64)(BW_UNIT - 1)) {
			bdp = ~(u64)0;
		} else {
			bdp += (u64)(BW_UNIT - 1);
		}
		return bdp >> BW_SCALE;
	}
}

/* kcc_bdp_packets scaled to bytes (saturating). */
static u64 kcc_bdp_bytes(u64 bw, u32 min_rtt_us, u32 gain, u32 mss) {
	u64 pkts = kcc_bdp_packets(bw, min_rtt_us, gain);
	u64 unit = (mss > 0) ? mss : 1460u;
	if (pkts > (~(u64)0) / unit) return ~(u64)0;
	return pkts * unit;
}

static void kcc_bw_update(struct kcc_core *k, s64 bw, u32 rtt_cnt) {
	if (bw <= 0) return;
	/* Rate samples can arrive several times within one delivery round.
	 * Keep the best sample for that round rather than letting each ACK
	 * overwrite one of the ten RTT-window entries. */
	if (k->bw_sample_count > 0 &&
	    k->bw_samples[k->bw_sample_cur].rtt_cnt == rtt_cnt) {
		if (bw > k->bw_samples[k->bw_sample_cur].val)
			k->bw_samples[k->bw_sample_cur].val = bw;
		return;
	}
	if (k->bw_sample_count == 0) {
		k->bw_sample_count = 1;
		k->bw_sample_cur = 0;
		k->bw_samples[0].val = bw;
		k->bw_samples[0].rtt_cnt = rtt_cnt;
		return;
	}
	int next = (int)((k->bw_sample_cur + 1) % KCC_BW_RT_CYCLE_LEN);
	k->bw_samples[next].val = bw;
	k->bw_samples[next].rtt_cnt = rtt_cnt;
	k->bw_sample_cur = (u32)next;
	if (k->bw_sample_count < KCC_BW_RT_CYCLE_LEN) k->bw_sample_count++;
}

static s64 kcc_bw_max(const struct kcc_core *k) {
	if (0 == k->bw_sample_count) return 0;
	s64 result = 0;
	u32 cur_rtt = k->rtt_cnt;
	for (u32 i = 0; i < k->bw_sample_count; i++) {
		if (cur_rtt - k->bw_samples[i].rtt_cnt >= KCC_BW_RT_CYCLE_LEN) continue;
		if (k->bw_samples[i].val > result) result = k->bw_samples[i].val;
	}
	if (0 == result && k->bw_sample_count > 0) {
		for (u32 i = 0; i < k->bw_sample_count; i++) {
			if (k->bw_samples[i].val > result) result = k->bw_samples[i].val;
		}
	}
	return result;
}

static void kcc_geodesic_update(struct kcc_core *k, s64 rtt_us, int round_start) {
	u32 rtt = (u32)(rtt_us > KCC_RTT_MIN_FLOOR_US ? rtt_us : KCC_RTT_MIN_FLOOR_US);
	u64 z = (u64)rtt << KCC_SCALE_SHIFT;

	if (0 == k->sample_cnt) {
		k->x_est = z;
		k->p_est = KCC_P_EST_INIT;
		k->qdelay_avg = 0;
		k->jitter_ewma = rtt >> KCC_JITTER_SEED_SHIFT;
		if (k->jitter_ewma < 1) k->jitter_ewma = 1;
		k->sample_cnt = 1;
		return;
	}

	if (1 == k->sample_cnt && k->min_rtt_us != MIN_RTT_UNINIT && k->min_rtt_us > 0) {
		u64 ceiling = (u64)k->min_rtt_us << KCC_SCALE_SHIFT;
		if (k->x_est > ceiling) k->x_est = ceiling;
	}

	{
		s64 innovation = (s64)z - (s64)k->x_est;
		u64 abs_innov = innovation >= 0 ? (u64)innovation : (u64)(-(innovation + 1)) + 1;

		if (innovation <= 0) {
			/* G1: instant downward absorption. */
			k->x_est = kcc_min_u64(k->x_est, z);
		} else if (round_start) {
			/* G2: bounded geometric growth, once per round, capped at z. */
			u64 growth = k->x_est * KCC_G2_GROWTH_NUM / KCC_G2_GROWTH_DEN;
			u64 new_x = k->x_est + growth;
			if (new_x < k->x_est) new_x = 0xFFFFFFFFFFFFFFFFull;
			k->x_est = kcc_min_u64(new_x, z);
		}

		/* Staleness: downward-only pull-back to 95% of min_rtt. */
		if (k->min_rtt_us != MIN_RTT_UNINIT &&
		    k->rtt_cnt - k->mr_update_rtt_cnt >= KCC_STALENESS_RNDS) {
			u64 mr_scaled = (u64)k->min_rtt_us << KCC_SCALE_SHIFT;
			if (k->x_est <= mr_scaled * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
				u64 target = mr_scaled * KCC_PD_NOISE_GATE_NUM / KCC_PD_NOISE_GATE_DEN;
				u64 lowered = kcc_min_u64(k->x_est, target);
				k->x_est = lowered > (u64)KCC_SCALE ? lowered : (u64)KCC_SCALE;
				k->mr_update_rtt_cnt = k->rtt_cnt;
			}
		}

		{
			u32 raw_jitter = (u32)((abs_innov >> KCC_SCALE_SHIFT) > 0xFFFFFFFFull
									   ? 0xFFFFFFFFu
									   : (u32)(abs_innov >> KCC_SCALE_SHIFT));
			k->jitter_ewma = (k->sample_cnt > 1)
								 ? (u32)(((u64)k->jitter_ewma * KCC_EWMA_JITTER_NUM +
										  (u64)raw_jitter) / KCC_EWMA_JITTER_DEN)
								 : raw_jitter;
			u32 jitter_cap = (k->min_rtt_us != MIN_RTT_UNINIT)
								 ? kcc_max_u32(k->min_rtt_us, KCC_RTT_SAMPLE_MAX_US)
								 : (u32)KCC_RTT_SAMPLE_MAX_US;
			if (k->jitter_ewma > jitter_cap) k->jitter_ewma = jitter_cap;
		}

		{
			/* Queue delay is measured against the confirmed propagation
			 * baseline (min_rtt), not against the per-ACK x_est. */
			u64 t_prop_scaled = (k->min_rtt_us != MIN_RTT_UNINIT && k->min_rtt_us > 0)
				? ((u64)k->min_rtt_us << KCC_SCALE_SHIFT) : k->x_est;
			u32 qdelay_instant = (z > t_prop_scaled)
				? (u32)((z - t_prop_scaled) >> KCC_SCALE_SHIFT) : 0;
			if (1 == k->sample_cnt) {
				k->qdelay_avg = qdelay_instant;
			} else {
				k->qdelay_avg = (u32)(((u64)k->qdelay_avg * KCC_EWMA_QDELAY_NUM + qdelay_instant) /
									  KCC_EWMA_QDELAY_DEN);
			}
		}

		if (k->sample_cnt < 0xFFFFFFFFu) k->sample_cnt++;

		if (k->sample_cnt >= KCC_MIN_SAMPLES) {
			u32 p_floor = KCC_P_EST_FLOOR;
			u64 x_est_us = k->x_est >> KCC_SCALE_SHIFT;
			if (x_est_us <= (u64)k->min_rtt_us * KCC_G3_SLOW_TH_NUM / KCC_G3_SLOW_TH_DEN &&
				!k->confirm_cnt && !k->confirm_slow_cnt) {
				u32 delta = k->p_est > p_floor ? (k->p_est - p_floor) >> KCC_P_EST_DECAY_SHIFT : 0;
				if (k->p_est > p_floor + delta) k->p_est -= (delta > 1 ? delta : 1);
			} else if (x_est_us > (u64)k->min_rtt_us * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
				u32 delta = k->p_est < KCC_P_EST_INIT ? (KCC_P_EST_INIT - k->p_est) >> KCC_P_EST_GROWTH_SHIFT : 0;
				if (k->p_est + delta < KCC_P_EST_MAX) k->p_est += (delta > 1 ? delta : 1);
			}
		}
	}
}

static void kcc_update_min_rtt(struct kcc_core *k, s64 rtt_us, s64 now_us, int round_start) {
	u32 rtt;
	u32 mr_snapshot;
	if (rtt_us <= 0) return;

	rtt = (u32)rtt_us;
	mr_snapshot = k->min_rtt_us;

	kcc_geodesic_update(k, rtt_us, round_start);

	/* Cold start: replace the 1ms placeholder with the first real sample. */
	if (k->sample_cnt == 1 && !k->has_seen_rtt &&
	    k->min_rtt_us == KCC_DEFAULT_RTT_US) {
		k->min_rtt_us = rtt;
	}

	if (rtt < KCC_LOCK_THRESH_US && k->min_rtt_us <= KCC_LOCK_THRESH_US) {
		k->locked = 1;
	}

	if (round_start) {
		u32 round_min = k->prev_round_rtt_min;
		u64 stat;
		int fire = 0;

		if (round_min == 0 || round_min == MIN_RTT_UNINIT) {
			k->confirm_cnt = 0;
			k->confirm_slow_cnt = 0;
		} else if (k->locked) {
			if (round_min >= KCC_FAST_ONLY_THRESH_US) {
				if (k->locked_high_cnt < KCC_BITFIELD_3BIT_MAX) {
					k->locked_high_cnt++;
				}
				if (k->locked_high_cnt >= KCC_BITFIELD_3BIT_MAX) {
					k->locked = 0;
					k->locked_high_cnt = 0;
					k->min_rtt_us = round_min;
					k->min_rtt_stamp = (u32)now_us;
					k->srtt_suppress_cnt = KCC_SRTT_SUPPRESS_RNDS;
					k->srtt_guard_cnt = 0;
				}
			} else {
				k->locked_high_cnt = 0;
			}
			k->confirm_cnt = 0;
			k->confirm_slow_cnt = 0;
		} else {
			stat = (u64)round_min << KCC_SCALE_SHIFT;

			if (round_min >= KCC_FAST_ONLY_THRESH_US) {
				if (stat >= (u64)k->min_rtt_us * KCC_SCALE * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
					if (k->confirm_cnt < KCC_BITFIELD_3BIT_MAX) k->confirm_cnt++;
				} else {
					k->confirm_cnt = 0;
				}
				if (stat >= (u64)k->min_rtt_us * KCC_SCALE * KCC_G3_SLOW_TH_NUM / KCC_G3_SLOW_TH_DEN) {
					if (k->confirm_slow_cnt < KCC_BITFIELD_3BIT_MAX) k->confirm_slow_cnt++;
				} else {
					k->confirm_slow_cnt = 0;
				}
			} else if (round_min >= KCC_LOCK_THRESH_US) {
				/* Gray zone (5ms <= round_min < 7.5ms): fast-only. */
				if (stat >= (u64)k->min_rtt_us * KCC_SCALE * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
					if (k->confirm_cnt < KCC_BITFIELD_3BIT_MAX) k->confirm_cnt++;
				} else {
					k->confirm_cnt = 0;
				}
				k->confirm_slow_cnt = 0;
			} else {
				k->confirm_cnt = 0;
				k->confirm_slow_cnt = 0;
			}

			/* Baseline return: a round at or below min_rtt resets both. */
			if (stat <= (u64)k->min_rtt_us * KCC_SCALE) {
				k->confirm_cnt = 0;
				k->confirm_slow_cnt = 0;
			}

			if (k->confirm_cnt >= KCC_G3_FAST_CNT) {
				fire = 1;
			} else if (k->confirm_slow_cnt >= KCC_G3_SLOW_CNT) {
				fire = 1;
			}
			if (fire) {
				k->min_rtt_us = round_min;
				k->min_rtt_stamp = (u32)now_us;
				k->confirm_cnt = 0;
				k->confirm_slow_cnt = 0;
				k->p_est = KCC_P_EST_INIT;
				k->mr_update_rtt_cnt = k->rtt_cnt;
				k->srtt_suppress_cnt = KCC_SRTT_SUPPRESS_RNDS;
				k->srtt_guard_cnt = 0;
			}
		}
	}

	/* Traditional min_rtt: no immediate first-sample reduction. */
	if (rtt <= k->min_rtt_us) {
		u32 r = rtt > KCC_RTT_MIN_FLOOR_US ? rtt : KCC_RTT_MIN_FLOOR_US;
		if ((u64)r < (u64)k->min_rtt_us * KCC_MINRTT_STICKY_NUM / KCC_MINRTT_STICKY_DEN) {
			if (round_start) {
				k->min_rtt_fast_fall_cnt = k->min_rtt_fast_fall_cnt < KCC_BITFIELD_3BIT_MAX
					? k->min_rtt_fast_fall_cnt + 1 : KCC_BITFIELD_3BIT_MAX;
			}
			if (r < k->min_rtt_us / KCC_MINRTT_FAST_FALL_DIV) {
				if (k->min_rtt_fast_fall_cnt >= KCC_MINRTT_FAST_FALL_FAST_CNT) {
					k->min_rtt_us = r;
					k->min_rtt_fast_fall_cnt = 0;
				}
			} else if (k->min_rtt_fast_fall_cnt >= KCC_MINRTT_FAST_FALL_CNT) {
				k->min_rtt_us = r;
				k->min_rtt_fast_fall_cnt = 0;
			}
		} else {
			k->min_rtt_us = r;
			k->min_rtt_fast_fall_cnt = 0;
		}
		k->min_rtt_stamp = (u32)now_us;
	} else {
		k->min_rtt_fast_fall_cnt = 0;
	}

	/* SRTT guard: sk->srtt_us is xtcp's unscaled microsecond value. */
	if (k->srtt_suppress_cnt) {
		if (round_start) k->srtt_suppress_cnt--;
		k->srtt_guard_cnt = 0;
	} else if (k->srtt_us && k->min_rtt_us) {
		u32 srtt_shifted = k->srtt_us > KCC_RTT_MIN_FLOOR_US ? k->srtt_us : KCC_RTT_MIN_FLOOR_US;
		if ((u64)srtt_shifted < (u64)k->min_rtt_us * KCC_MINRTT_SRTT_GUARD_NUM / KCC_MINRTT_SRTT_GUARD_DEN) {
			if (round_start && k->srtt_guard_cnt < KCC_BITFIELD_3BIT_MAX) k->srtt_guard_cnt++;
			if (k->srtt_guard_cnt >= KCC_MINRTT_FAST_FALL_CNT) {
				k->min_rtt_us = srtt_shifted;
				k->min_rtt_stamp = (u32)now_us;
				k->srtt_guard_cnt = 0;
			}
		} else {
			k->srtt_guard_cnt = 0;
		}
	}

	/* Downward path-change detection on the completed round's minimum. */
	if (round_start && k->prev_round_rtt_min != 0 &&
	    k->prev_round_rtt_min != MIN_RTT_UNINIT) {
		u32 round_min = k->prev_round_rtt_min;
		if (round_min < k->min_rtt_us &&
		    round_min < (u64)k->min_rtt_us * KCC_PD_NOISE_GATE_NUM / KCC_PD_NOISE_GATE_DEN) {
			if (k->x_est_fall_cnt < KCC_MINRTT_FAST_FALL_CNT) k->x_est_fall_cnt++;
			if (k->x_est_fall_cnt >= KCC_MINRTT_FAST_FALL_CNT) {
				k->min_rtt_us = round_min;
				k->x_est_fall_cnt = 0;
				k->min_rtt_stamp = (u32)now_us;
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

static u32 kcc_get_cycle_pacing_gain(const struct kcc_core *k) {
	u32 idx = k->cycle_idx % KCC_PROBE_BW_CYCLE_LEN;
	switch (idx) {
	case 0: return (u32)(BBR_UNIT * GAIN_PROBE_PHASE_NUM / GAIN_PROBE_PHASE_DEN);
	case 1: return (u32)(BBR_UNIT * GAIN_DRAIN_PHASE_NUM / GAIN_DRAIN_PHASE_DEN);
	default: return BBR_UNIT;
	}
}

/* Kernel kcc_packets_in_net_at_edt (tcp_kcc.c:5016-5037):
 *
 *   interval_us        = (edt - now) in MICROSECONDS
 *   interval_delivered = (bw * interval_us) >> BW_SCALE   (truncated to u32)
 *   inflight_at_edt    = inflight_pkts + (gain > BBR_UNIT ? tso_segs_goal : 0)
 *   credit >= inflight_at_edt -> 0
 *   else (inflight_at_edt - credit) * mss
 *
 * The kernel counts packets; callers here compare against kcc_bdp_bytes, so
 * the packet result is scaled back to bytes with mss. edt_us is the pacing
 * queue depth (tp->tcp_wstamp_ns - now, microseconds). */

/* Kernel kcc_quantization_budget (tcp_kcc.c:3859-3864):
 *   cwnd += KCC_TSO_HEADROOM_MULT * kcc_tso_segs_goal(sk);
 *   cwnd  = (cwnd + 1) & ~1U;
 * kcc_inflight() = kcc_quantization_budget(kcc_bdp(...)), and both the DRAIN
 * target and its ssthresh go through it (audit B6-D2). */
static u64 kcc_quantization_budget(u64 cwnd, u32 tso_segs_goal) {
	return (cwnd + (u64)KCC_TSO_HEADROOM_MULT * tso_segs_goal + 1) & ~(u64)1;
}

/* Kernel kcc_tso_segs_goal (tcp_kcc.c:3689-3697) with the port's pinned
 * defaults (no sk_pacing_shift / GSO_MAX_SIZE socket fields):
 *   bytes = min(pacing_rate >> 10, 65536 - 1 - 120)
 *   segs  = max(bytes / mss, min_tso_segs), capped at 127
 * kcc_min_tso_segs (tcp_kcc.c:3651-3672): 1 below KCC_MIN_TSO_RATE/div,
 * 2 at or above it, with div halved (8 -> 4) under high jitter. */
static u32 kcc_tso_segs_goal(const struct kcc_core *k) {
	u32 div = KCC_MIN_TSO_RATE_DIV;
	u64 bytes;
	u64 segs;
	u32 min_segs;
	u64 thresh;

	if (k->jitter_ewma > KCC_TSO_HIGH_JITTER_THRESH_US) {
		div = (div >> KCC_TSO_DIV_HALVE_SHIFT) > 0
			? (div >> KCC_TSO_DIV_HALVE_SHIFT) : 1;
	}
	thresh = (KCC_MIN_TSO_RATE / div) > 0 ? (KCC_MIN_TSO_RATE / div) : 1;
	min_segs = ((u64)k->pacing_rate_bytes_per_second < thresh)
		? KCC_TSO_SEGS_LOW : KCC_TSO_SEGS_DEFAULT;

	bytes = (u64)k->pacing_rate_bytes_per_second >> 10;
	if (bytes > (u64)(65536 - 1 - 120)) bytes = (u64)(65536 - 1 - 120);
	if (0 == k->mss) return min_segs;
	segs = bytes / k->mss;
	if (segs < min_segs) segs = min_segs;
	return (segs > KCC_TSO_MAX_SEGS) ? (u32)KCC_TSO_MAX_SEGS : (u32)segs;
}

static u64 kcc_packets_in_net_at_edt(u64 inflight_bytes, u32 gain, u32 mss,
				     u64 bw_pkts, u32 edt_us, u32 tso_segs_goal) {
	u64 unit = (mss > 0) ? mss : 1460u;
	u64 inflight_pkts = (inflight_bytes + unit - 1) / unit;
	u32 credit;
	if (gain > BBR_UNIT) inflight_pkts += tso_segs_goal;
	/* Kernel: u32 interval_delivered = (u64)kcc_bw * interval_us >> BW_SCALE
	 * - the product truncates to u32 (tcp_kcc.c:5023-5024). */
	{
		u64 c = (bw_pkts * (u64)edt_us) >> BW_SCALE;
		credit = (c > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (u32)c;
	}
	if ((u64)credit >= inflight_pkts) return 0;
	return (inflight_pkts - (u64)credit) * unit;
}

static int kcc_is_next_cycle_phase(const struct kcc_core *k, s64 now_us,
				   s64 losses, s64 flight_bytes, u32 edt_us) {
	u64 elapsed = now_us > (s64)k->cycle_mstamp_us
		? (u64)(now_us - (s64)k->cycle_mstamp_us) : 0;
	int is_full_length = elapsed > k->min_rtt_us;
	u32 gain = kcc_get_cycle_pacing_gain(k);
	u64 inflight = kcc_packets_in_net_at_edt(flight_bytes, gain, k->mss,
					     (u64)k->max_bw, edt_us, kcc_tso_segs_goal(k));
	u64 target;

	if (gain == BBR_UNIT) {
		return is_full_length;
	}
	if (gain > BBR_UNIT) {
		target = kcc_bdp_bytes((u64)k->max_bw, k->min_rtt_us, gain, k->mss);
		return (is_full_length &&
			(losses > 0 || inflight >= target)) ||
			elapsed > (u64)k->min_rtt_us * 2;
	}
	target = kcc_bdp_bytes((u64)k->max_bw, k->min_rtt_us, BBR_UNIT, k->mss);
	return (is_full_length && inflight <= target) ||
		elapsed > (u64)k->min_rtt_us * 4;
}

static void kcc_advance_cycle_phase(struct kcc_core *k, s64 now_us) {
	k->cycle_idx = (k->cycle_idx + 1) % KCC_PROBE_BW_CYCLE_LEN;
	k->cycle_mstamp_us = (u64)now_us;
}

/* Kernel kcc_reset_probe_bw_mode: random initial phase, never 1. */
static void kcc_reset_probe_bw_mode(struct kcc_core *k, s64 now_us) {
	u32 r = kcc_rand_below(&k->rand_state, KCC_PROBE_BW_CYCLE_LEN - 1);
	k->mode = KCC_MODE_PROBE_BW;
	k->cycle_idx = (KCC_PROBE_BW_CYCLE_LEN - 1) - r;
	k->cycle_idx = (k->cycle_idx + 1) % KCC_PROBE_BW_CYCLE_LEN;
	k->cycle_mstamp_us = (u64)now_us;
}

static void kcc_update_cycle_phase(struct kcc_core *k, s64 now_us,
				   s64 losses, s64 flight_bytes, u32 edt_us) {
	if (k->mode == KCC_MODE_PROBE_BW &&
	    kcc_is_next_cycle_phase(k, now_us, losses, flight_bytes, edt_us)) {
		kcc_advance_cycle_phase(k, now_us);
	}
}

static void kcc_check_full_bw_reached_gated(struct kcc_core *k, int round_start,
					    int is_app_limited) {
	if (k->full_bw_reached || !round_start || is_app_limited) return;
	{
		u64 bw = (u64)kcc_bw_max(k);
		u64 thresh = (k->full_bw * KCC_FULL_BW_THRESH) >> BBR_SCALE;
		if (bw >= thresh) {
			k->full_bw = bw;
			k->full_bw_cnt = 0;
		} else {
			k->full_bw_cnt++;
		}
		if (k->full_bw_cnt >= KCC_FULL_BW_CNT) k->full_bw_reached = 1;
	}
}

struct kcc_ack_input {
	s64 now_us;
	s64 delivered_bytes;
	s64 delivered_pkts;
	s64 rtt_us;
	s64 flight_bytes;
	s64 prior_in_flight_bytes;
	s64 losses;
	s64 prior_delivered_pkts;
	s64 delivered_total_pkts;
	int is_ack_delayed;
	int is_app_limited;
	u32 edt_us;              /* interval_to_edt (microseconds) */
};

static void kcc_check_full_bw_reached_gated(struct kcc_core *k, int round_start,
					    int is_app_limited);

static void kcc_update_model(struct kcc_core *k, const struct kcc_ack_input *in) {
	const s64 now_us = in->now_us;
	/* KCC's model lives in the KERNEL PACKET domain (tp->delivered counts
	 * tcp_skb_pcount); the byte-domain input is kept only for the caller. */
	const s64 delivered = in->delivered_pkts;
	const s64 rtt_us = in->rtt_us;
	const s64 flight_bytes = in->flight_bytes;
	const s64 losses = in->losses;
	s64 interval_us = now_us - (s64)k->prev_ack_us;
	int round_start;
	s64 bw = 0;

	if (interval_us < 0) interval_us = 0;

	/* Kernel kcc_update_bw: delivered-round boundary (packet domain). */
	round_start = (interval_us > 0) &&
		(in->prior_delivered_pkts >= k->next_rtt_delivered);
	if (round_start) {
		k->next_rtt_delivered = in->delivered_total_pkts;
		k->rtt_cnt++;
		k->packet_conservation = 0;
		k->prev_round_rtt_min = k->round_rtt_min;
		k->round_rtt_min = MIN_RTT_UNINIT;
	}

	if (delivered > 0 && interval_us > 0) {
		bw = (delivered << BW_SCALE) / interval_us;
		/* Kernel clamps to U32_MAX (a plain cast would wrap). */
		if ((u64)bw > (u64)KCC_BW_SEG_MAX) bw = (s64)KCC_BW_SEG_MAX;
	}
	if (!in->is_app_limited || (u64)bw >= (u64)kcc_bw_max(k)) {
		kcc_bw_update(k, bw, k->rtt_cnt);
	}
	k->max_bw = kcc_bw_max(k);
	kcc_update_ack_aggregation(k, (u64)(delivered > 0 ? delivered : 0), (u64)now_us,
				   round_start);

	/* Kernel kcc_is_next_cycle_phase measures rs->prior_in_flight (the
	 * in-flight snapshot taken BEFORE this ACK cleaned the queue). */
		kcc_update_cycle_phase(k, now_us, losses, in->prior_in_flight_bytes,
					in->edt_us);
	kcc_check_full_bw_reached_gated(k, round_start, in->is_app_limited);

	/* Kernel kcc_check_drain. */
	if (k->mode == KCC_MODE_STARTUP && k->full_bw_reached) {
		k->mode = KCC_MODE_DRAIN;
		k->drain_enter_stamp_us = (u64)now_us;
		if (k->mss > 0) {
			/* Kernel kcc_check_drain: snd_ssthresh = kcc_inflight(...), i.e. the
			 * BDP WITH the quantization budget (audit B6-D2). */
			u64 segs = kcc_quantization_budget(
				kcc_bdp_packets((u64)k->max_bw, k->min_rtt_us, BBR_UNIT),
				kcc_tso_segs_goal(k));
			if (segs > 0x7FFFFFFFull) segs = 0x7FFFFFFFull;
			k->snd_ssthresh = (u32)segs;
		}
	}
	if (k->mode == KCC_MODE_DRAIN) {
		u64 inflight = kcc_packets_in_net_at_edt((u64)flight_bytes, k->pacing_gain,
						k->mss, (u64)k->max_bw, in->edt_us, kcc_tso_segs_goal(k));
		/* Kernel comparison target is kcc_inflight (BDP + budget). */
		u64 bdp = kcc_quantization_budget(
			kcc_bdp_packets((u64)k->max_bw, k->min_rtt_us, BBR_UNIT),
			kcc_tso_segs_goal(k)) * (u64)((k->mss > 0) ? k->mss : 1460u);
		u64 elapsed = (now_us > (s64)k->drain_enter_stamp_us)
			? (u64)(now_us - (s64)k->drain_enter_stamp_us) : 0;
		u64 min_rtt = (k->min_rtt_us == MIN_RTT_UNINIT) ? 0 : k->min_rtt_us;
		int drained = inflight <= bdp;
		int one_rtt = elapsed > min_rtt;
		int timeout = elapsed > min_rtt * 4;
		if ((drained && one_rtt) || timeout) {
			kcc_reset_probe_bw_mode(k, now_us);
		}
	}

	if (rtt_us > 0) {
		kcc_update_min_rtt(k, rtt_us, now_us, round_start);
		if (!in->is_ack_delayed && (u32)rtt_us < k->round_rtt_min) {
			k->round_rtt_min = (u32)rtt_us;
		}
	}
	if (delivered > 0) {
		k->idle_restart = 0;
	}

	/* Mode/gain assignment */
	switch (k->mode) {
	case KCC_MODE_STARTUP:
		k->pacing_gain = KCC_HIGH_GAIN;
		k->cwnd_gain = KCC_HIGH_GAIN;
		break;
	case KCC_MODE_DRAIN:
		k->pacing_gain = KCC_DRAIN_GAIN;
		k->cwnd_gain = KCC_HIGH_GAIN;
		break;
	case KCC_MODE_PROBE_BW:
		k->pacing_gain = kcc_get_cycle_pacing_gain(k);
		k->cwnd_gain = KCC_CWND_GAIN;
		break;
	default:
		break;
	}
}

static void kcc_set_pacing_rate(struct kcc_core *k, u64 bw, s32 gain) {
	u64 rate;
	u64 mss = (k->mss > 0) ? k->mss : 1460u;
	if (bw == 0) bw = (u64)BW_UNIT;
	/* Kernel clamps the packet-domain estimate to U32_MAX, then converts
	 * with bw * mss (kcc_rate_bytes_per_sec). */
	if (bw > (u64)KCC_BW_SEG_MAX) bw = (u64)KCC_BW_SEG_MAX;
	rate = kcc_haircut_scale(kcc_mul_shr8(bw * mss, (u32)gain));
	if (!k->has_seen_rtt && k->min_rtt_us > 0 && k->min_rtt_us != MIN_RTT_UNINIT &&
	    k->mss > 0) {
		u64 rtt;
		u64 cwnd_segs;
		u64 bdp_bw;
		u64 boot_rate;
		k->has_seen_rtt = 1;
		rtt = k->min_rtt_us > 0 ? k->min_rtt_us : 1;
		cwnd_segs = (u64)k->congestion_window_bytes / k->mss;
		bdp_bw = (cwnd_segs * (u64)BW_UNIT) / rtt;
		boot_rate = bdp_bw * k->mss;
		boot_rate = kcc_haircut_scale(kcc_mul_shr8(boot_rate, KCC_HIGH_GAIN));
		if (boot_rate > rate) rate = boot_rate;
	}
	if (k->full_bw_reached) {
		k->pacing_rate_bytes_per_second =
			(s64)((rate < k->max_pacing_rate) ? rate : k->max_pacing_rate);
	} else {
		/* Kernel kcc_bw_to_pacing_rate clamps EVERY rate it returns with
		 * min_t(u64, rate, sk->sk_max_pacing_rate) (tcp_kcc.c:3563-3567),
		 * so the monotonic gate compares capped values. */
		u64 capped = (rate < k->max_pacing_rate) ? rate : k->max_pacing_rate;
		if (capped > (u64)k->pacing_rate_bytes_per_second) {
			k->pacing_rate_bytes_per_second = (s64)capped;
		}
	}
}

static void kcc_set_cwnd(struct kcc_core *k, u64 bw, s32 gain, s64 acked,
			 s64 delivered_total_pkts, s64 losses) {
	u64 mss = (k->mss > 0) ? k->mss : 1460u;
	/* Kernel kcc_set_cwnd works in PACKETS (tp->snd_cwnd is packets). */
	u64 cwnd = (u64)k->cwnd_segs;
	int conserve = 0;

	if (acked > 0) {
		if (losses > 0) {
			/* Kernel kcc_set_cwnd (tcp_kcc.c:3992-3998) subtracts
			 * rs->losses, which is already a PACKET count
			 * (tcp_input_66.c:3936). No byte->packet rounding here. */
			u64 lost_pkts = (u64)losses;
			cwnd = (lost_pkts < cwnd)
				? cwnd - lost_pkts
				: (u64)KCC_CWND_ABSOLUTE_MIN;
		}
		/* Kernel kcc_set_cwnd_to_recover_or_restore (kcc_set_cwnd opens
		 * with it). Mirrors the C++ port field for field:
		 *   Open -> Recovery (first): packet_conservation = 1,
		 *       next_rtt_delivered = delivered, cwnd = inflight + acked
		 *   Recovery -> Open: cwnd = max(cwnd, prior_cwnd), cons = 0
		 * While packet_conservation is set the sample only releases what
		 * was acknowledged (no additive growth this round). */
		if (k->ca_state == 3 && k->prev_ca_state != 3) {
			k->packet_conservation = 1;
			k->next_rtt_delivered = delivered_total_pkts;
			cwnd = (u64)((k->flight_bytes + mss - 1) / mss) + (u64)acked;
		} else if (k->prev_ca_state >= 3 && k->ca_state < 3) {
			if (k->prior_cwnd > cwnd) cwnd = (u64)k->prior_cwnd;
			k->packet_conservation = 0;
		}
		if (k->ca_state != k->prev_ca_state) {
			k->prev_ca_state = k->ca_state;
		}
		if (k->packet_conservation) {
			u64 floor_cwnd = (u64)((k->flight_bytes + mss - 1) / mss) + (u64)acked;
			if (floor_cwnd > cwnd) cwnd = floor_cwnd;
			conserve = 1;
		}
	}
	if (!conserve && acked > 0) {
		if (k->min_rtt_us != MIN_RTT_UNINIT && k->min_rtt_us > 0) {
			u64 target = kcc_bdp_packets(bw, k->min_rtt_us, (u32)gain);
			/* Linux bbr_set_cwnd: + ack_aggregation_cwnd, then
			 * quantization budget (mirrors the C++ port). */
			target += kcc_ack_aggregation_cwnd(k);
			target = kcc_quantization_budget(target, kcc_tso_segs_goal(k));
			if (k->mode == KCC_MODE_PROBE_BW && k->cycle_idx == 0) {
				target += 2;  /* KCC_PROBE_CWND_BONUS (segs) */
			}
			if (k->full_bw_reached) {
				u64 grown = cwnd + (u64)acked;
				if (grown < cwnd) grown = ~(u64)0;
				cwnd = (grown < target) ? grown : target;
			} else if (cwnd < target || (u64)delivered_total_pkts < 10ull) {
				u64 grown = cwnd + (u64)acked;
				if (grown < cwnd) grown = ~(u64)0;
				cwnd = grown;
			}
		}
	}
	if (cwnd < (u64)KCC_CWND_MIN_TARGET) {
		cwnd = (u64)KCC_CWND_MIN_TARGET;
	}
	k->congestion_window_bytes = (s64)(cwnd * mss);
	k->cwnd_segs = (cwnd > 0x7FFFFFFFull) ? 0x7FFFFFFFll : (s64)cwnd;
}

/* ---- Public API (fidelity differential driver) ---- */

void kcc_core_init(struct kcc_core *k) {
	memset(k, 0, sizeof(*k));
	k->min_rtt_us = KCC_DEFAULT_RTT_US;
	k->min_rtt_stamp = 0;
	k->mr_update_rtt_cnt = 0;
	k->mode = KCC_MODE_STARTUP;
	k->pacing_gain = KCC_HIGH_GAIN;
	k->cwnd_gain = KCC_HIGH_GAIN;
	k->p_est = KCC_P_EST_INIT;
	k->congestion_window_bytes = 10 * 1460;
	k->cwnd_segs = 10;
	k->round_rtt_min = MIN_RTT_UNINIT;
	k->prev_round_rtt_min = MIN_RTT_UNINIT;
	k->idle_restart = 0;
	k->drain_enter_stamp_us = 0;
	k->next_rtt_delivered = 0;
	k->snd_ssthresh = 0x7FFFFFFFu;
	k->max_pacing_rate = ~(u64)0;  /* kernel default: no cap */
}

void kcc_core_set_random_seed(struct kcc_core *k, u32 seed) {
	if (k) k->rand_state = seed;
}

void kcc_core_on_ack(struct kcc_core *k, s64 now_us, s64 delivered_bytes,
		     s64 rtt_us, s64 flight_bytes, s64 losses,
		     s64 prior_delivered, s64 delivered_total,
		     int is_ack_delayed, int is_app_limited, u32 edt_us) {
	struct kcc_ack_input in;
	s64 acked = delivered_bytes > 0 ? delivered_bytes : 0;
	s64 sample_interval = now_us - (s64)k->last_ack_us;
	s64 provisional_bw;

	if (sample_interval < 0) sample_interval = 0;
	provisional_bw = (delivered_bytes > 0 && sample_interval > 0)
		? (delivered_bytes << BW_SCALE) / sample_interval : 0;
	if (provisional_bw > 0 && k->mss > 0) {
		u64 cap = (u64)KCC_BW_SEG_MAX * k->mss;
		if ((u64)provisional_bw > cap) provisional_bw = (s64)cap;
	}

	in.now_us = now_us;
	in.delivered_bytes = delivered_bytes;
	in.delivered_pkts = acked;
	in.rtt_us = rtt_us;
	in.flight_bytes = flight_bytes;
	in.prior_in_flight_bytes = flight_bytes;
	in.losses = losses;
	in.prior_delivered_pkts = prior_delivered;
	in.delivered_total_pkts = delivered_total;
	in.is_ack_delayed = is_ack_delayed;
	in.is_app_limited = is_app_limited;
	in.edt_us = edt_us;

	k->flight_bytes = (u32)flight_bytes;
	k->prev_delivered = k->total_delivered;
	k->total_delivered += acked;
	k->prev_ack_us = k->last_ack_us;
	k->last_ack_us = (u64)now_us;

	kcc_update_model(k, &in);

	kcc_set_pacing_rate(k, k->max_bw > 0 ? (u64)k->max_bw : (u64)provisional_bw,
			    (s32)k->pacing_gain);
	kcc_set_cwnd(k, (u64)k->max_bw, (s32)k->cwnd_gain, acked,
		     delivered_total, losses);
}

/**
 * @brief Packet-domain entry point: the driver supplies the kernel-domain
 *        delivered counts (segments) plus the pre-ACK in-flight snapshot.
 */
void kcc_core_on_ack_pkts(struct kcc_core *k, s64 now_us, s64 delivered_pkts,
			  s64 rtt_us, s64 flight_bytes, s64 prior_in_flight_bytes,
			  s64 losses, s64 prior_delivered_pkts,
			  s64 delivered_total_pkts, int is_ack_delayed,
			  int is_app_limited, u32 edt_us) {
	struct kcc_ack_input in;
	s64 acked = delivered_pkts > 0 ? delivered_pkts : 0;
	s64 sample_interval = now_us - (s64)k->last_ack_us;
	s64 provisional_bw;

	if (sample_interval < 0) sample_interval = 0;
	provisional_bw = (delivered_pkts > 0 && sample_interval > 0)
		? (delivered_pkts << BW_SCALE) / sample_interval : 0;
	if (provisional_bw > 0) {
		if ((u64)provisional_bw > (u64)KCC_BW_SEG_MAX)
			provisional_bw = (s64)KCC_BW_SEG_MAX;
	}

	in.now_us = now_us;
	in.delivered_bytes = 0;
	in.delivered_pkts = delivered_pkts;
	in.rtt_us = rtt_us;
	in.flight_bytes = flight_bytes;
	in.prior_in_flight_bytes = prior_in_flight_bytes;
	in.losses = losses;
	in.prior_delivered_pkts = prior_delivered_pkts;
	in.delivered_total_pkts = delivered_total_pkts;
	in.is_ack_delayed = is_ack_delayed;
	in.is_app_limited = is_app_limited;
	in.edt_us = edt_us;

	k->flight_bytes = (u32)flight_bytes;
	k->prev_delivered = k->total_delivered;
	k->total_delivered += acked;
	k->prev_ack_us = k->last_ack_us;
	k->last_ack_us = (u64)now_us;

	kcc_update_model(k, &in);

	kcc_set_pacing_rate(k, k->max_bw > 0 ? (u64)k->max_bw : (u64)provisional_bw,
			    (s32)k->pacing_gain);
	kcc_set_cwnd(k, (u64)k->max_bw, (s32)k->cwnd_gain, acked,
		     delivered_total_pkts, losses);
}

/* Kernel kcc_cwnd_event (portable subset: CA_EVENT_TX_START only). */
void kcc_core_cwnd_event(struct kcc_core *k, int event, int app_limited) {
	if (!k || event != 5 || !app_limited) return;
	k->idle_restart = 1;
	if (k->mode == KCC_MODE_PROBE_BW) {
		k->cycle_mstamp_us = k->last_ack_us;
		kcc_set_pacing_rate(k, k->max_bw > 0 ? (u64)k->max_bw : (u64)BW_UNIT,
				    BBR_UNIT);
	}
}

void kcc_core_get_snapshot(const struct kcc_core *k, struct kcc_snapshot *out) {
	if (!k || !out) return;
	out->x_est = k->x_est;
	out->max_bw = (u64)k->max_bw;
	out->full_bw = k->full_bw;
	out->p_est = k->p_est;
	out->qdelay_avg = k->qdelay_avg;
	out->jitter_ewma = k->jitter_ewma;
	out->sample_cnt = k->sample_cnt;
	out->min_rtt_us = k->min_rtt_us;
	out->rtt_cnt = k->rtt_cnt;
	out->confirm_cnt = k->confirm_cnt;
	out->confirm_slow_cnt = k->confirm_slow_cnt;
	out->locked = k->locked;
	out->locked_high_cnt = k->locked_high_cnt;
	out->min_rtt_fast_fall_cnt = k->min_rtt_fast_fall_cnt;
	out->x_est_fall_cnt = k->x_est_fall_cnt;
	out->srtt_guard_cnt = k->srtt_guard_cnt;
	out->srtt_suppress_cnt = k->srtt_suppress_cnt;
	out->round_rtt_min = k->round_rtt_min;
	out->prev_round_rtt_min = k->prev_round_rtt_min;
	out->mode = k->mode;
	out->pacing_gain = k->pacing_gain;
	out->cwnd_gain = k->cwnd_gain;
	out->cycle_idx = k->cycle_idx;
	out->full_bw_reached = k->full_bw_reached;
	out->full_bw_cnt = k->full_bw_cnt;
	out->has_seen_rtt = k->has_seen_rtt;
	out->idle_restart = k->idle_restart;
	out->next_rtt_delivered = (u64)k->next_rtt_delivered;
	out->total_delivered = (u64)k->total_delivered;
	out->cycle_mstamp_us = k->cycle_mstamp_us;
	out->last_ack_us = k->last_ack_us;
	out->drain_enter_stamp_us = k->drain_enter_stamp_us;
	out->rand_state = k->rand_state;
	out->ca_state = k->ca_state;
	out->prev_ca_state = k->prev_ca_state;
	out->prior_cwnd = k->prior_cwnd;
	out->packet_conservation = k->packet_conservation;
}

u64  kcc_core_x_est(const struct kcc_core *k) { return k->x_est; }
u32  kcc_core_p_est(const struct kcc_core *k) { return k->p_est; }
u32  kcc_core_qdelay(const struct kcc_core *k) { return k->qdelay_avg; }
u32  kcc_core_min_rtt(const struct kcc_core *k) { return k->min_rtt_us; }
s64  kcc_core_cwnd_segs(const struct kcc_core *k) { return k->cwnd_segs; }
s64  kcc_core_pacing_rate(const struct kcc_core *k) { return k->pacing_rate_bytes_per_second; }
u32  kcc_core_mode(const struct kcc_core *k) { return k->mode; }
