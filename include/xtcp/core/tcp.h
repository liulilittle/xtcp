#pragma once

/**
 * @file tcp.h
 * @brief TCP segment format (RFC 793), connection state machine (minimal
 *        set), listener with SYN queue.
 *
 * RFC acceptance gates for this unit: RFC 793 (state table, segment
 * processing), RFC 1122 section 4.2 (host requirements), RFC 5961
 * (blind-attack mitigation: RST validation, challenge ACK).
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>
#include <xtcp/core/timer.h>
#include <xtcp/core/tfo.h>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace xtcp {
    namespace cc {
        // Forward declarations: the CC hook table lives in cc/cc.h; TcpConn
        // only holds a pointer to it and opaque sample values.
        struct XtcpCongestionOps;
        struct RateSample;
        struct AckSample;
    }
    namespace core {
        /**
         * @brief Per-connection fields the CC hooks operate on (kernel
         *        tcp_sock field equivalents, same names and semantics).
         */
        struct XtcpConnCc {
            UInt32  snd_cwnd       = 10;      /**< Congestion window (packets); RFC 6928 initial window (10 segs, Linux initcwnd) */
            UInt32  snd_ssthresh   = 0x7FFFFFFF;
            UInt64  pacing_rate    = 0;       /**< Bytes per second */
            /**
             * @brief Kernel sk->sk_max_pacing_rate: the hard ceiling a CC
             *        algorithm may not pace above (SO_MAX_PACING_RATE).
             *        The kernel default is ~0U (no limit), which is what
             *        this mirrors; kcc_bw_to_pacing_rate applies
             *        min_t(u64, rate, sk_max_pacing_rate)
             *        (tcp_kcc.c:3563-3567).
             */
            UInt64  max_pacing_rate = 0xFFFFFFFFFFFFFFFFull;
            UInt64  delivered      = 0;       /**< Total bytes delivered */
            UInt64  delivered_mstamp = 0;     /**< Last delivery timestamp (ms) */
            UInt64  lost           = 0;       /**< Total lost bytes */
            /**
             * @brief Kernel tp->lost equivalent in PACKETS: the count of
             *        segments freshly marked lost since the last rate sample.
             *        rate_sample.losses is this domain (tcp_input_66.c:3936
             *        `lost = tp->lost - lost`), and KCC subtracts it from cwnd
             *        directly (`cwnd -= rs->losses`, tcp_kcc.c:3993). The
             *        byte-domain `lost` above stays for BBR/CUBIC.
             */
            UInt32  lost_pkts      = 0;
            UInt64  lsndtime       = 0;       /**< Last send time (ms) */
            UInt32  srtt_us        = 0;       /**< Smoothed RTT (us) */
            UInt32  mdev_us        = 0;       /**< RTT variance (us) */
            UInt32  mss            = 1460;
            UInt32  rtt_min_us     = 0;       /**< min RTT (us) */
            UInt32  rcv_wnd        = 65535;
            UInt32  snd_wnd        = 65535;
            UInt32  inflight       = 0;       /**< Bytes in flight */
            /**
             * @brief Kernel tp->app_limited marker (u32 wrap semantics):
             *        0 = not app-limited; otherwise the (UInt32) delivered+
             *        inflight watermark latched at the send entry.  Cleared
             *        only when delivered passes the watermark using the
             *        kernel after() comparison.
             */
            UInt32  app_limited    = 0;
            UInt32  snd_cwnd_cnt   = 0;       /**< Bytes acked toward the next CA increment (kernel tcp_sock equivalent) */
            /**
             * @brief Kernel tp->delivered equivalent in PACKETS (segments):
             *        cumulative ACKs and newly SACKed segments both count
             *        (tcp_count_delivered). KCC's delivered-round and
             *        bandwidth math use this domain; the byte-domain
             *        `delivered` above is unchanged for BBR/CUBIC.
             */
            UInt64  delivered_pkts = 0;
            /** @brief Kernel icsk_ca_state (0=Open,1=Disorder,2=CWR,
             *         3=Recovery,4=Loss) for the CC recovery hooks. */
            Byte    ca_state = 0;
            UInt32  prior_cwnd = 0;           /**< Kernel tp->prior_cwnd */
            UInt32  prior_ssthresh = 0;       /**< Kernel tp->prior_ssthresh */
            Byte    packet_conservation = 0;  /**< Kernel kcc packet_conservation */
            void*   ca_priv        = NULLPTR; /**< Algorithm private state */
        };

        /**
         * @brief RFC 1982 sequence comparison: true when a is "before" b.
         */
        inline bool SeqLt(UInt32 a, UInt32 b) noexcept {
            return static_cast<Int32>(a - b) < 0;
        }
        inline bool SeqLe(UInt32 a, UInt32 b) noexcept {
            return a == b || SeqLt(a, b);
        }

        /**
         * @brief TCP protocol states (RFC 793).
         */
        enum class TcpState : Byte {
            kClosed      = 0,
            kListen      = 1,
            kSynSent     = 2,
            kSynRcvd     = 3,
            kEstablished = 4,
            kFinWait1    = 5,
            kFinWait2    = 6,
            kCloseWait   = 7,
            kLastAck     = 8,
            kClosing     = 9,
            kTimeWait    = 10,
        };

        /**
         * @brief TCP flags (RFC 793).
         */
        enum TcpFlag : UInt16 {
            kFlagFin  = 0x0001,
            kFlagSyn  = 0x0002,
            kFlagRst  = 0x0004,
            kFlagPsh  = 0x0008,
            kFlagAck  = 0x0010,
            kFlagUrg  = 0x0020,
            kFlagEce  = 0x0040,
            kFlagCwr  = 0x0080,
        };

        /**
         * @brief TCP header; options parsed via ParseTcpOpts/TcpOpts
         *        (MSS, wscale, SACK, timestamps, TFO cookie, MD5).
         */
        struct TcpHdr {
            UInt16 sport   = 0;
            UInt16 dport   = 0;
            UInt32 seq     = 0;
            UInt32 ack     = 0;
            UInt16 flags   = 0;   /**< Flag field (fin..cwr, 8 bits parsed) */
            UInt16 window  = 0;
            UInt16 checksum = 0;
            UInt16 urgent  = 0;
            Byte    hdr_len = 20;  /**< Header length in bytes */
            UInt16 payload_off = 20;

            bool IsSyn() const noexcept { return 0 != (flags & kFlagSyn); }
            bool IsAck() const noexcept { return 0 != (flags & kFlagAck); }
            bool IsFin() const noexcept { return 0 != (flags & kFlagFin); }
            bool IsRst() const noexcept { return 0 != (flags & kFlagRst); }
            bool IsEce() const noexcept { return 0 != (flags & kFlagEce); }
            bool IsCwr() const noexcept { return 0 != (flags & kFlagCwr); }
            bool IsUrg() const noexcept { return 0 != (flags & kFlagUrg); }
        };

        /**
         * @brief Parses a TCP header from a segment.
         * @param data Segment bytes.
         * @param len  Segment length.
         * @param out  Filled on success.
         * @return True when the header is valid.
         */
        bool ParseTcp(const Byte* data, UInt32 len, TcpHdr& out) noexcept;

        /**
         * @brief Parsed TCP options (RFC 793 / RFC 7323).
         */
        struct TcpOpts {
            bool    has_wscale  = false;
            Byte    wscale      = 0;    /**< Window scale factor (0-14) */
            bool    has_sack    = false;
            bool    has_timestamp = false;
            UInt32  ts_val      = 0;
            UInt32  ts_ecr      = 0;
            bool    has_mss     = false;
            UInt16  mss         = 1460;
            Byte    sack_count  = 0;    /**< SACK blocks present (RFC 2018) */
            UInt32  sack[4][2]  = { { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 } };  /**< [left, right) edges */
            bool    has_tfo     = false;/**< TFO cookie present (RFC 7413) */
            Byte    tfo_cookie[8] = { 0 };
        };

        /**
         * @brief Parses TCP options from a segment.
         * @param data Segment bytes (TCP header start).
         * @param len  Segment length.
         * @param hdr_len TCP header length (from the data-offset field).
         * @param out  Filled on success.
         * @return True when options parse without malformation.
         */
        bool ParseTcpOpts(const Byte* data, UInt32 len, UInt32 hdr_len, TcpOpts& out) noexcept;

        /**
         * @brief Endpoint (family + address + port).
         */
        struct Endpoint {
            Byte    family = 4;
            UInt32  addr[4] = { 0, 0, 0, 0 };
            UInt16  port   = 0;
        };

        /**
         * @brief Output sink: receives complete IP packets to transmit.
         */
        typedef std::function<void(buf::BufRef&&)> TxSink;
        /**
         * @brief Received in-order data callback.
         * @param data Buffer (valid only during the callback).
         * @param len  Bytes.
         * @return true when the data was accepted; false rejects it (back-
         *         pressure). A rejected segment is not acknowledged: rcv_nxt_
         *         does not advance, so the peer RTOs and retransmits instead
         *         of silently losing application data.
         */
        typedef std::function<bool(const Byte* data, UInt32 len)> RecvCallback;
        /**
         * @brief Timer-driven state-change notification (the stack registers
         *        it so timer-only transitions - RTO exhaustion, keepalive
         *        abort, FIN-WAIT-2 timeout - can reach the application).
         * @param state The new state (e.g. kClosed).
         */
        typedef std::function<void(TcpState state)> StateChangeCallback;

        /**
         * @brief TCP connection: state machine with retransmission, RTO
         *        (Jacobson, RFC 6298), sliding window, fast retransmit.
         * @note The shard drives timers via NextRetransmitTime() /
         *       OnRetransmitTimer() with monotonic time.
         */
        class TcpConn {
        public:
            /**
             * @brief Our RFC 7323 window-scale offer (shift count sent in
             *        every SYN). The scale takes effect only when the peer
             *        answers WSOPT (both-sides rule): rcv_wscale_ is set to
             *        this value at handshake completion iff the peer's
             *        SYN/SYN+ACK carried the option, else 0 (unscaled).
             */
            static constexpr Byte kWindowScaleOffer = 7;

            TcpConn(TcpState state, const Endpoint& local, const Endpoint& remote, UInt32 iss, UInt32 irs, TxSink sink) noexcept;
            virtual ~TcpConn() noexcept;

            /**
             * @brief Selects the congestion-control algorithm by name.
             * @param name Registered algorithm (cc/cc.h), or NULLPTR/empty
             *        for the built-in Reno (RFC 5681) default.
             * @return True when the algorithm was found and installed, or when
 *         NULLPTR/empty selected the built-in Reno default.
             */
            bool SetCongestionControl(const char* name) noexcept;

            /**
             * @brief Processes one incoming TCP segment (IP payload).
             * @param data Segment bytes.
             * @param len  Segment length.
             * @param now  Monotonic time (microseconds) for RTT sampling.
             */
            void OnSegment(const Byte* data, UInt32 len, TimePoint now = 0) noexcept;
            /**
             * @brief Sends application data (window permitting).
             * @param data Payload bytes (referenced only during the call).
             * @param len  Payload length.
             * @param now  Monotonic time.
 * @return True when the data was accepted (sent or buffered); false when the
 *         call cannot accept it - the per-connection send quota is exhausted
 *         (caller must back off and retry later) or the connection is not in
 *         a send-ready state (handshake in flight / closing). A full window
 *         or a pacing gate buffers the data instead of failing
 *         (full Linux send semantics).
             */
            bool SendData(const Byte* data, UInt32 len, TimePoint now) noexcept;
            /**
             * @brief Re-sends buffered data after a window update.
             * @param now Monotonic time.
             */
            void Flush(TimePoint now) noexcept;
            /**
             * @brief Sends app data queued during the SYN/SYN+ACK handshake
             *        once the connection is Established (full client mode).
             * @param now Monotonic time.
             */
            void FlushPendingSend(TimePoint now) noexcept;
            /**
             * @brief Fires every due timer (delayed-ACK, RTO, persist) and
             *        flushes buffered sends under ONE lock acquisition.
             * @param now Monotonic time.
             * @return Number of timers fired.
             */
            UInt32 OnPoll(TimePoint now) noexcept;
            /**
             * @brief Bytes currently buffered for sending (window/pacing
             *        constrained). 0 = nothing pending.
             */
            UInt32 PendingSendBytes() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return static_cast<UInt32>(pending_send_.size());
            }
            /**
 * @brief Initiates active close (sends FIN).
 * @param now Monotonic time (currently unused - the implementation reads
 *        its own monotonic clock; kept for signature stability).
             */
            void Close(TimePoint now = 0) noexcept;
            /**
             * @brief Aborts the connection (sends RST).
             */
            void Abort() noexcept;
            /**
             * @brief Sends an empty ACK segment.
             */
            void SendAck() noexcept;
            /**
             * @brief Sends the SYN segment (active-open path, SynSent).
             * @note Caller invokes after creating the connection in SynSent.
             */
            void SendSyn() noexcept;
            /**
             * @brief Sends SYN with early data (TCP Fast Open, RFC 7413).
             * @param data Early payload (zero-RTT data).
             * @param len  Payload length.
             * @return True when sent (SynSent).
             */
            bool SendSynWithData(const Byte* data, UInt32 len) noexcept;
            /**
             * @brief Accepts early data carried in a SYN (server side).
             * @param data Payload bytes.
             * @param len  Payload length.
             */
            void AcceptEarlyData(const Byte* data, UInt32 len) noexcept;
            /**
             * @brief Arms the delayed ACK to announce the receive-window
             *        reopening after backpressure (RFC 1122 s4.2.3.4: the
             *        receiver must advertise a nonzero window when it can
             *        accept data again - without it, recovery waits on the
             *        peer's persist probe).
             */
            void ArmWindowUpdateAck(TimePoint now) noexcept;
            /**
             * @brief Sends the SYN+ACK segment (passive-open path, SynRcvd).
             */
            void SendSynAck() noexcept;
            /**
             * @brief Builds a stateless SYN+ACK (SYN-cookie mode, RFC 4987):
             *        the ISN carries the cookie, no connection is created.
             * @param local  Our endpoint (the listener).
             * @param remote Peer endpoint.
             * @param cookie ISN (the computed cookie).
             * @param ack    ACK value (peer SYN seq + 1).
             * @param wscale Our advertised window-scale factor.
             * @return Packet ready to transmit; empty on allocation failure.
             */
            static buf::BufRef BuildSynAckPacket(const Endpoint& local, const Endpoint& remote,
                                                 UInt32 cookie, UInt32 ack, Byte wscale,
                                                 const Byte* md5_key = NULLPTR,
                                                 UInt32 md5_key_len = 0) noexcept;
            /**
             * @brief Next retransmission deadline, 0 when none pending.
             */
            TimePoint NextRetransmitTime() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return rto_deadline_;
            }
            /**
             * @brief Next ACK deadline (delayed ACK), 0 when none pending.
             */
            TimePoint NextAckTime() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return ack_deadline_;
            }

            /**
             * @brief Enables TCP-MD5 (RFC 2385) with the given key.
             * @param key Secret key bytes.
             * @param key_len Key length in bytes (0 disables MD5).
             */
            void SetMd5Key(const Byte* key, UInt32 key_len) noexcept {
                md5_key_len_ = (NULLPTR == key || 0 == key_len) ? 0 : key_len;
                if (0 < md5_key_len_) {
                    md5_key_len_ = (64 < md5_key_len_) ? 64 : md5_key_len_;
                    std::memcpy(md5_key_, key, md5_key_len_);
                }
            }
            /**
             * @brief True when TCP-MD5 signing is enabled.
             */
            bool Md5Enabled() const noexcept { return 0 < md5_key_len_; }
            /**
             * @brief Current MD5 key (or NULLPTR when disabled).
             */
            const Byte* Md5Key() const noexcept { return (0 < md5_key_len_) ? md5_key_ : NULLPTR; }
            UInt32 Md5KeyLen() const noexcept { return md5_key_len_; }
            /**
             * @brief Records the peer's advertised MSS (RFC 879).
             * @note A TCP_MAXSEG user ceiling (user_mss_, Linux semantics)
             *       caps every application of the peer's MSS: the effective
             *       send MSS never exceeds min(user_mss_, peer MSS). The
             *       ceiling applies to the handshake value too, so a
             *       pre-connect maxseg setting is honored (Linux parity).
             */
            void SetPeerMss(UInt16 mss) noexcept {
                // RFC 1122 §4.2.2.6: an MSS option of 0 means the peer did not
                // signal a usable MSS - use the IPv4 default of 536 (a 0 MSS
                // would divide by zero in cwnd math). Sub-256 values are
                // unusable in practice, so clamp them up too.
                if (0 == mss) {
                    mss = 536;
                } else if (mss < 256) {
                    mss = 256;
                }
                if (0 < user_mss_ && user_mss_ < mss) {
                    mss = static_cast<UInt16>(user_mss_);  // TCP_MAXSEG ceiling
                }
                peer_mss_ = mss;
                cc_.mss = mss;
            }
            UInt16 PeerMss() const noexcept { return peer_mss_; }
            /** @brief TCP_MAXSEG ceiling (Linux semantics); 0 = unset. */
            void SetUserMss(UInt32 mss) noexcept { user_mss_ = mss; }
            UInt32 UserMss() const noexcept { return user_mss_; }
            /**
             * @brief RFC 2385: verifies the TCP-MD5 digest of an inbound
             *        segment (t = the TCP segment, local/remote = this side's
             *        endpoints for an inbound segment from the peer).
             * @return true when the digest matches (or no MD5 option is present).
             */
            static bool VerifyMd5Segment(const Byte* key, UInt32 key_len,
                                         const Endpoint& local, const Endpoint& remote,
                                         Byte* t, UInt32 tcp_len) noexcept;
            /**
             * @brief RFC 1191 path-MTU reduction: lowers the effective MSS
             *        after an ICMP "fragmentation needed" for this flow, and
             *        arms the periodic re-probe (the path may have grown).
             * @param next_hop_mtu MTU announced by the router.
             */
            void OnMtuReduced(UInt16 next_hop_mtu) noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                // RFC 879 floor: never let the MSS fall below 256 - a
                // spoofed/pathological ICMP must not force byte-at-a-time sending.
                UInt32 new_mss = (next_hop_mtu > 40) ? (next_hop_mtu - 40) : 256;
                if (new_mss < 256) {
                    new_mss = 256;
                }
                if (new_mss < peer_mss_) {
                    if (0 == orig_peer_mss_) {
                        orig_peer_mss_ = peer_mss_;  // remember the negotiated MSS
                    }
                    peer_mss_ = static_cast<UInt16>(new_mss);
                    cc_.mss = peer_mss_;
                    ResplitRetransQueue(static_cast<UInt16>(new_mss));
                    mtu_probe_deadline_ = MtuNowUs() + mtu_probe_interval_;
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
            }
            /**
             * @brief Sets the periodic MTU re-probe interval (RFC 1191:
             *        the path MTU may have increased). Default 600 s.
             */
            void SetMtuProbeInterval(UInt32 us) noexcept { mtu_probe_interval_ = (0 == us) ? 1 : us; }
            /**
             * @brief Monotonic microseconds (steady clock).
             */
            static UInt64 MtuNowUs() noexcept {
                return static_cast<UInt64>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
            }

            /**
             * @brief Sets the per-connection send buffer quota (bytes).
             *        Bounds the retransmission queue, hence the connection's
             *        worst-case memory: snd_buf_ + ooo limit + fixed overhead.
             */
            void SetSndBuf(UInt32 bytes) noexcept { snd_buf_ = (0 == bytes) ? kMinSndBuf : bytes; }
            UInt32 SndBuf() const noexcept { return snd_buf_; }
            /**
             * @brief In-flight unacknowledged bytes (send-side occupancy).
             */
            UInt32 SndInflight() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return snd_nxt_ - snd_una_;
            }
            /**
             * @brief Current congestion window (segments).
             */
            UInt32 Cwnd() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.snd_cwnd;
            }
            /**
             * @brief Smoothed RTT in microseconds (0 before the first sample).
             */
            UInt32 SrttUs() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return srtt_;
            }
            /**
             * @brief Current slow-start threshold (segments).
             */
            UInt32 Ssthresh() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.snd_ssthresh;
            }
            /**
             * @brief Peer's currently advertised window (bytes).
             */
            UInt32 SndWnd() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return snd_wnd_;
            }
            /**
             * @brief Total retransmissions performed.
             */
            UInt32 RetransmitCount() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return retransmit_count_;
            }
            /**
             * @brief Kernel tp->total_retrans (PACKETS): retransmissions
             *        counted by tcp_skb_pcount, the domain the DSACK
             *        credibility gate compares against.
             */
            UInt32 TotalRetransPkts() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return total_retrans_pkts_;
            }
            /** @brief Kernel tp->app_limited marker (0 = not limited). */
            UInt32 AppLimitedMarker() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.app_limited;
            }
            /** @brief Kernel tp->delivered (PACKETS). */
            UInt64 DeliveredPkts() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.delivered_pkts;
            }
            /** @brief Kernel tp->lost_out (PACKETS). */
            UInt32 LostOutPkts() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return lost_out_pkts_;
            }
            /** @brief Kernel tp->retrans_out (PACKETS). */
            UInt32 RetransOutPkts() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return retrans_out_pkts_;
            }
            /** @brief Kernel tp->dsack_dups (DSACK segments seen). */
            UInt32 DsackDups() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return dsack_dups_;
            }
            /**
             * @brief Seconds-worth of MSL x2: how long TIME-WAIT connections
             *        linger before reclamation (RFC 793 2MSL). Default 120 s.
             */
            void SetTwoMsl(UInt32 us) noexcept { two_msl_us_ = (0 == us) ? 1 : us; }
            /**
             * @brief Fast-path poll skip: false when this connection has no
             *        armed timers and no buffered sends, so the stack-wide
             *        sweep skips it without locking (lock-free read).
             */
            bool TimersDirty() const noexcept {
                return timers_dirty_.load(std::memory_order_relaxed);
            }
            UInt64 TimeWaitDeadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return timewait_deadline_;
            }
            /**
             * @brief Enables/disables immediate ACKs (Linux TCP_QUICKACK):
             *        one-shot semantics - the flag auto-clears after the
             *        first ACK, so re-enable via SetOption each time.
             */
            void SetQuickAck(bool on) noexcept { quickack_ = on; }
            /**
             * @brief RFC 2018: records whether the peer advertised
             *        SACK-permitted on its SYN/SYN+ACK (the server learns it
             *        from the client's SYN; the client from the SYN+ACK).
             */
            void SetSackOk(bool on) noexcept { sack_ok_ = on; }
            /** @brief RFC 7323: the peer's SYN carried the TSopt (both sides
             *         must offer for the option to activate). */
            void SetPeerTimestampsOffered(bool on) noexcept { peer_ts_offered_ = on; }
            /**
             * @brief Enables TSO direct-sends: super-MSS application sends
             *        go to the backend in ONE segment (the NIC segments).
             *        Set by the stack on the connect path when the backend
             *        advertises kCapTsoTx and no tx qdisc is mounted. The send
             *        path still gates
             *        every direct send on an empty retransmission queue and
             *        the window/cwnd bounds - recovery is never entered
             *        with an oversized entry.
             */
            void SetTsoTx(bool on) noexcept { tso_tx_ = on; }
            /** @brief Whether TSO direct-sends are enabled. */
            bool TsoTx() const noexcept { return tso_tx_; }
            /** @brief Number of unacknowledged segments (diagnostics/tests:
             *         the TSO-direct gate requires an empty queue). */
            UInt32 RetransQueueSize() const noexcept {
                return static_cast<UInt32>(retrans_queue_.size());
            }
            /** @brief Diagnostics: the O(1) in-flight estimate (same value the
             *         CA_EVENT_TX_START gate and the CC hooks consume). */
            UInt32 PipeInFlightBytesPublic() const noexcept {
                return PipeInFlightBytes();
            }
            /** @brief Diagnostics ONLY: recompute the in-flight bytes by walking
             *         the queue, i.e. the O(N) cost the incremental counters
             *         replaced. Used to quantify the fix; never on a hot path. */
            UInt32 PipeWalkReference() const noexcept {
                UInt32 sacked = 0;
                UInt32 lost = 0;
                UInt32 retrans = 0;
                for (const SentSeg& seg : retrans_queue_) {
                    sacked += seg.sacked;
                    if (0 != seg.lost && seg.sacked < seg.len) {
                        lost += seg.len - seg.sacked;
                    }
                    if (0 != seg.is_retrans) {
                        retrans += seg.len - seg.sacked;
                    }
                }
                const UInt32 inflight = snd_nxt_ - snd_una_;
                const UInt32 left_out = sacked + lost;
                const UInt32 base = (inflight > left_out) ? (inflight - left_out) : 0;
                return base + retrans;
            }
            bool QuickAck() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return quickack_;
            }
            /**
             * @brief Sets the FIN-WAIT-2 timeout (Linux tcp_fin_timeout):
             *        after our FIN is ACKed, a peer that never sends its own
             *        FIN would hold the connection forever. Default 60 s.
             */
            void SetFinWait2Timeout(UInt32 us) noexcept { finwait2_timeout_ = (0 == us) ? 1 : us; }
            /**
             * @brief FIN-WAIT-2 reclamation deadline (0 = not armed).
             */
            UInt64 FinWait2Deadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return finwait2_deadline_;
            }
            /**
             * @brief Sets the SYN retransmission budget (Linux TCP_SYNCNT).
             *        After this many unanswered retransmits the handshake
             *        is abandoned. Default 6.
             */
            void SetSynRetries(UInt32 n) noexcept { syn_retries_ = n; }
            UInt32 SynRetries() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return syn_retries_;
            }
            /**
             * @brief Stores the peer's TFO cookie (RFC 7413) for a future
             *        fast-open SYN. Obtained from the SYN+ACK option.
             */
            void SetTfoCookie(const Byte* cookie) noexcept {
                if (NULLPTR != cookie) {
                    std::memcpy(tfo_cookie_, cookie, 8);
                    has_tfo_cookie_ = true;
                    if (tfo_cb_) {
                        tfo_cb_(cookie);
                    }
                } else {
                    has_tfo_cookie_ = false;
                }
            }
            void SetTfoCookieCallback(std::function<void(const Byte*)> cb) noexcept {
                tfo_cb_ = std::move(cb);
            }
            bool HasTfoCookie() const noexcept { return has_tfo_cookie_; }
            const Byte* TfoCookie() const noexcept { return has_tfo_cookie_ ? tfo_cookie_ : NULLPTR; }
            /**
             * @brief RFC 7413: verifies a client's TFO cookie (server side).
             *        The cookie is keyed by the CLIENT address (remote_), so
             *        a cookie generated for one client cannot be replayed
             *        from another IP (Generate must use the same address).
             */
            bool VerifyTfoCookie(const Byte* cookie) const noexcept {
                if (NULLPTR == cookie) {
                    return false;
                }
                UInt32 bound[4];
                TfoBoundAddr(bound);
                return tfo_.Check(bound, cookie);
            }
            /**
             * @brief Sets the base RTO (RFC 6298 default 1 s; tests and
             *        low-latency deployments may lower it).
             *
             *        The value is clamped to the 60 s UpdateRto cap so an
             *        over-large explicit RTO cannot stall retransmission for
             *        minutes at a time. The lower bound is left at 1 us: tests
             *        intentionally set sub-200 ms RTOs to speed up retry
             *        scenarios, and SetRto is an explicit configuration (the
             *        200 ms floor only applies to measured RTOs).
             */
            void SetRto(UInt32 us) noexcept {
                rto_ = (0 == us) ? 1 : us;
                if (rto_ > 60ull * 1000000u) {
                    rto_ = 60 * 1000000u;  // 60 s cap, mirrors UpdateRto
                }
            }
            void EnterTimeWait(TimePoint now) noexcept {
                timewait_deadline_ = now + two_msl_us_;
                // Defensive: a TIME-WAIT conn must stay in the sweep so it is
                // reclaimed at the deadline. The normal call sites pair this
                // with Transition(kTimeWait) (which sets dirty), but a future
                // direct caller must not strand the conn un-swept forever
                // (conn-cap leak).
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
            /**
             * @brief Configures keepalive (Linux TCP_KEEPIDLE/INTVL/CNT).
             * @param idle_us Idle time before the first probe (0 = disabled).
             * @param intvl_us Probe interval.
             * @param cnt     Failed probes before aborting the connection.
             * @note Linux parity: disabling (idle_us = 0) does NOT reset the
             *       unanswered-probe counter. Re-enabling after unanswered
             *       probes with a smaller cnt can abort at the next idle
             *       check (keepalive audit m3 - documented, not a bug).
             */
            void SetKeepalive(UInt64 idle_us, UInt64 intvl_us, UInt32 cnt) noexcept {
                keepalive_idle_ = idle_us;
                keepalive_intvl_ = (0 == intvl_us) ? 1000000 : intvl_us;
                keepalive_cnt_ = (0 == cnt) ? 8 : cnt;
                if (0 < keepalive_idle_) {
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
            }
            /**
             * @brief TCP_USER_TIMEOUT (Linux parity): the maximum time the
             *        oldest unacknowledged segment may stay outstanding before
             *        the connection is aborted (0 = disabled; the RTO-retry
             *        budget still bounds it). The check runs on the timer
             *        sweep, so the abort fires without any packet activity.
             */
            void SetUserTimeout(UInt64 timeout_us) noexcept {
                user_timeout_us_ = timeout_us;
                if (0 < user_timeout_us_) {
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
            }
            /** @brief Configured TCP_USER_TIMEOUT (0 = disabled). */
            UInt64 UserTimeout() const noexcept { return user_timeout_us_; }
            /**
             * @brief Next zero-window persist probe time (0 = none pending).
             */
            UInt64 PersistDeadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return persist_deadline_;
            }
            /**
             * @brief Sets the persist probe interval (RFC 1122 zero-window
             *        probing). Default 1 s, exponential backoff to 60 s.
             *        The probe itself is fired by OnPersistTimer.
             */
            void SetPersistInterval(UInt32 us) noexcept {
                persist_interval_ = (0 == us) ? 1 : us;
                persist_base_ = persist_interval_;
            }
            /**
             * @brief Fires the RFC 1122 zero-window probe (1 byte).
             */
            void OnPersistTimer(TimePoint now) noexcept;
            /**
             * @brief Current pacing rate (bytes/sec) of a connection.
             */
            UInt64 PacingRate() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.pacing_rate;
            }
            UInt64 KeepaliveIdle() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return keepalive_idle_;
            }
            UInt64 KeepaliveInterval() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return keepalive_intvl_;
            }
            UInt32 KeepaliveCount() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return keepalive_cnt_;
            }
            /**
             * @brief Duplicate-ACK counter.
             */
            UInt32 DupAcks() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return dup_acks_;
            }
            /**
             * @brief True when RFC 5681 fast recovery is active.
             */
            bool FastRecovery() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return fast_recovery_;
            }
            /**
             * @brief Kernel tp->high_seq: snd_nxt snapshot of the current
             *        cwnd-reduction episode (0 = no episode). Read-only
             *        observability for the recovery state machine.
             */
            UInt32 HighSeq() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return high_seq_;
            }
            /**
             * @brief Kernel tp->undo_retrans (-1 = nothing retransmitted).
             *        Read-only observability for the recovery state machine.
             */
            Int32 UndoRetrans() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return undo_retrans_;
            }
            /**
             * @brief RFC 3522 Eifel: an RTO retransmission awaits its ACK
             *        (kernel tp->retrans_stamp presence). Read-only.
             */
            bool RtoPending() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return rto_pending_;
            }
            /**
             * @brief Sequence number of the oldest unacknowledged segment
             *        (the retransmit target), 0 when the queue is empty.
             */
            UInt32 FrontSeq() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return retrans_queue_.empty() ? 0 : retrans_queue_.front().seq;
            }
            /**
             * @brief Handles the retransmission timer (exponential backoff).
             * @param now Monotonic time.
             */
            void OnRetransmitTimer(TimePoint now) noexcept;
            /**
             * @brief Current RTO (microseconds).
             */
            UInt32 Rto() const noexcept { return rto_; }

            TcpState State() const noexcept { return state_; }
            UInt32 SndNxt() const noexcept { return snd_nxt_; }
            UInt32 SndUna() const noexcept { return snd_una_; }
            UInt32 RcvNxt() const noexcept { return rcv_nxt_; }
            UInt32 Window() const noexcept { return window_; }
            /**
             * @brief Bytes awaiting acknowledgment.
             */
            UInt32 InflightBytes() const noexcept { return snd_nxt_ - snd_una_; }
            /**
             * @brief A sent (possibly unacknowledged) segment retained for
             *        zero-copy retransmission. Public so the migration
             *        checkpoint can carry the retransmission queue.
             */
            struct SentSeg {
                UInt32      seq = 0;
                UInt32      len = 0;
                TimePoint   sent_at = 0;
                UInt32      rto = 0;       /**< Current per-segment RTO */
                UInt32      retries = 0;
                UInt32      sacked = 0;    /**< Bytes SACKed within this segment (RFC 6675 pipe) */
                UInt64      sent_delivered = 0; /**< cc_.delivered at last (re)transmit (bytes) */
                Byte        app_limited = 0;    /**< cc_.app_limited != 0 at last (re)transmit */
                Byte        is_retrans = 0;     /**< Data was (re)transmitted (TCPCB_RETRANS) */
                /**
                 * @brief Kernel tcp_skb_pcount equivalent: packets this
                 *        segment represents, ceil(len/mss) (tcp_output_v66.c
                 *        tcp_set_skb_tso_segs). Refreshed on every (re)
                 *        transmission, like the other send snapshots.
                 */
                UInt32      pkt_count = 1;
                /**
                 * @brief Kernel TCPCB tx.delivered (PACKETS): cc_.delivered_pkts
                 *        when this segment was last (re)transmitted. Feeds
                 *        RateSample.prior_delivered_pkts.
                 */
                UInt64      sent_delivered_pkts = 0;
                /**
                 * @brief Kernel TCPCB_LOST: this segment was declared lost
                 *        (per-segment, distinct from cc_.lost which is the
                 *        bytes-lost-since-last-sample accumulator).
                 */
                Byte        lost = 0;
                /**
                 * @brief Kernel TCPCB_SACKED_RETRANS retired early: the
                 *        segment was fully SACKed while marked LOST, so
                 *        retrans_out already dropped its pkt_count
                 *        (tcp_input_66.c:1392-1396). The pop path must not
                 *        decrement it a second time.
                 */
                Byte        retrans_out_retired = 0;
                buf::BufRef data;          /**< Payload reference (zero-copy retransmit) */
            };

            /**
             * @brief Serializes connection state for migration. Carries the
             *        full send-side transmission state so a migrated
             *        connection can still retransmit its in-flight segments
             *        and flush its buffered application data: a checkpoint
             *        with only the sequence numbers leaves the restored
             *        connection with snd_nxt_ > snd_una_ but no segments to
             *        retransmit - the RTO path sees an empty queue and the
             *        flow stalls forever (in-flight data unrecoverable).
             */
            struct ConnCheckpoint {
                TcpState state      = TcpState::kClosed;
                UInt32   snd_una    = 0;
                UInt32   snd_nxt    = 0;
                UInt32   rcv_nxt    = 0;
                UInt32   snd_wnd    = 65535;
                UInt32   window     = 65535;
                UInt32   rcv_wnd    = 65535;  /**< RX acceptance window (SetRcvBuf) - without it a migrated conn drops data beyond the default */
                Byte     rcv_wscale = 0;  /**< Negotiated receive scale (RFC 7323) */
                Byte     snd_wscale = 0;  /**< Peer's window scale (needed to read future window fields) */
                UInt32   rto        = 1000000;
                UInt32   srtt       = 0;
                UInt32   rttvar     = 0;
                std::vector<Byte>              pending_send;  /**< Buffered application bytes */
                std::deque<SentSeg>            retrans_queue; /**< In-flight, unacknowledged segments */
            };
            /**
             * @brief Produces a migration checkpoint.
             */
            ConnCheckpoint MakeCheckpoint() const noexcept;
            /**
             * @brief Applies a migration checkpoint (restore path).
             * @param ckpt State captured on the source shard.
             */
            void ApplyCheckpoint(const ConnCheckpoint& ckpt) noexcept;
            /**
             * @brief Installs the in-order receive callback.
             */
            void SetRecvHandler(RecvCallback cb) noexcept { recv_cb_ = std::move(cb); }
            /** @brief RFC 793 urgent-data notification (SO_OOBINLINE): fires
             *         once per URG segment, after the inline data delivery.
             *         The urgent bytes are delivered with the normal stream
             *         (the TCP semantics of the modern OOBINLINE usage). */
            void SetUrgentCallback(std::function<void()> cb) noexcept {
                urgent_cb_ = std::move(cb);
            }
            /**
             * @brief Installs the timer-driven state-change notification.
             */
            void SetStateChangeCallback(StateChangeCallback cb) noexcept { state_change_cb_ = std::move(cb); }
            /**
             * @brief Sets the TCP_NODELAY flag (Nagle disable).
             * @note Controls the Nagle algorithm (RFC 896 / Minshall
             *       variant: a small segment waits for aggregation while
             *       inflight >= MSS).
             */
            void SetNodelay(bool enabled) noexcept { nodelay_ = enabled; }
            /**
             * @brief TCP_NODELAY flag.
             */
            bool Nodelay() const noexcept { return nodelay_; }
            /**
             * @brief Requests ECN negotiation (RFC 3168) on this connection.
             * @param enabled When true, SYN carries the ECE flag.
             */
            void SetEcnRequested(bool enabled) noexcept { ecn_requested_ = enabled; }
            /**
             * @brief ECN requested on this connection (RFC 3168).
             */
            bool EcnRequested() const noexcept { return ecn_requested_; }
            /**
             * @brief Suppresses SACK-permitted on the SYN (RFC 5827 ER tests
             *        and kernel tcp_sack=0 parity): the connection then runs
             *        without SACK, so RACK's sack_ok_ gate never fires and
             *        the Early-Retransmit dupthresh applies.
             * @param disabled When true, the SYN omits SACK-permitted.
             */
            void SetNoSackPermitted(bool disabled) noexcept { no_sack_permitted_ = disabled; }
            /**
             * @brief SACK-permitted suppressed on this connection.
             */
            bool NoSackPermitted() const noexcept { return no_sack_permitted_; }
            /**
             * @brief ECN negotiated (both ends offered ECE).
             */
            bool EcnActive() const noexcept { return ecn_active_; }
            /**
             * @brief RFC 3168 s6.1.3: records that the receiver detected a
             *        CE-marked IP packet (ECN field = 11). The next ACKs then
             *        echo ECE until the sender answers with CWR.
             */
            void SetCeSeen() noexcept { ecn_ce_seen_ = true; }
            /**
             * @brief RFC 3168 s6.1.3: ACK flags include ECE once CE was
             *        detected on an ECN-active connection.
             */
            UInt16 AckFlags() const noexcept {
                return static_cast<UInt16>(kFlagAck |
                                           ((ecn_active_ && ecn_ce_seen_) ? kFlagEce : 0));
            }
            /**
             * @brief Advertised receive-window field (RFC 1122 s4.2.3.4):
             *        zero while the app is backpressuring (recv_cb_ rejected
             *        data) - the peer stops sending and persists instead of
             *        retransmitting into a window it cannot use. Recovered on
             *        the next accepted deliver. Reflects the out-of-order
             *        buffer occupancy: buffered OOO bytes are receive memory
             *        already consumed, so the free capacity is
             *        window_ - ooo_bytes_.
             */
            UInt16 AdvertisedWindow() const noexcept {
                if (rcv_blocked_ || ooo_bytes_ >= window_) {
                    return 0;
                }
                return static_cast<UInt16>((window_ - ooo_bytes_) >> rcv_wscale_);
            }
            /**
             * @brief Configures our receive-buffer capacity (the advertised
             *        receive window). The window the peer may fill, bounded by
             *        the negotiated scale's representable range. Larger values
             *        raise the per-connection in-flight ceiling on high-BDP
             *        links; the default (65535) matches the legacy behavior.
             * @param bytes Receive capacity in bytes (clamped to
             *        [1, 65535 << 7]).
             */
            void SetRcvBuf(UInt32 bytes) noexcept {
                constexpr UInt32 kMaxRcvBuf = 65535u << 7;  // wscale 7 offer ceiling
                const UInt32 v = (bytes < 1) ? 1u : ((bytes > kMaxRcvBuf) ? kMaxRcvBuf : bytes);
                window_ = v;
                rcv_wnd_ = v;
                cc_.rcv_wnd = v;
            }
            /**
             * @brief Sets our advertised window-scale factor (0-14, RFC 7323).
             */
            void SetRcvWscale(Byte factor) noexcept { rcv_wscale_ = (14 < factor) ? 14 : factor; }
            /**
             * @brief Peer's negotiated window-scale factor.
             */
            Byte SndWscale() const noexcept { return snd_wscale_; }
            /**
             * @brief Sets the peer's window-scale factor (passive-open path).
             */
            void SetSndWscale(Byte factor) noexcept { snd_wscale_ = (14 < factor) ? 14 : factor; }

        private:
            void Transition(TcpState next) noexcept;
            void SendSegment(UInt32 seq, UInt32 ack, UInt16 flags, const Byte* payload, UInt32 payload_len) noexcept;
            Byte BuildSackRanges(UInt32* out, Byte max_pairs) const noexcept;
            void SendChallengeAck() noexcept;
            void SendDupAck() noexcept;
            void UpdateRto(UInt32 sample_us) noexcept;
            void ArmRetransmit(TimePoint now, UInt32 interval_us = 0) noexcept;
            void RetransmitFront(TimePoint now, bool fresh_ts = false) noexcept;
            void ResplitRetransQueue(UInt16 new_mss) noexcept;
            void OnAckReceived(UInt32 ack, bool ece, TimePoint now, const TcpOpts* opts) noexcept;
            void RackDetectLoss(TimePoint now) noexcept;
            UInt32 PipeBytes() const noexcept;
            /**
             * @brief Kernel tcp_packets_in_flight() equivalent in bytes:
             *        packets_out - left_out + retrans_out, i.e.
             *        inflight - sacked + retransmitted (tcp_h_v66.h:1217).
             *        A lost segment stops counting as in-flight, so this is
             *        the CA_EVENT_TX_START gate (tcp_output_v66.c:167-168),
             *        NOT the raw sequence-space distance.
             */
            UInt32 PipeInFlightBytes() const noexcept;
            /**
             * @brief Adds/removes one segment's contribution to the O(1)
             *        pipe counters. `sign` is +1 on insert, -1 on erase.
             *
             * Kept separate from the queue mutation so every call site reads
             * the same three terms the walk used to compute:
             *   sacked  = seg.sacked
             *   lost    = (seg.lost && seg.sacked < seg.len) ? len - sacked : 0
             *   retrans = (0 < seg.retries) ? len - sacked : 0
             */
            void PipeAccountSeg(const SentSeg& seg, int sign) noexcept;
            /**
             * @brief Same as PipeAccountSeg but from plain values, so a caller
             *        can describe a segment's PREVIOUS state without copying it
             *        (SentSeg owns a BufRef and is not copyable). The retransmit
             *        term is keyed on `is_retrans` (kernel TCPCB_SACKED_RETRANS).
             */
            void PipeAccountFields(UInt32 len, UInt32 sacked, Byte lost,
                                   Byte is_retrans, int sign) noexcept;
            /**
             * @brief Re-derives one segment's pipe terms after a field of that
             *        segment changed (seg.sacked / seg.lost / seg.is_retrans).
             *        `old_sacked`/`old_lost`/`old_is_retrans` are the values
             *        BEFORE the mutation.
             */
            void PipeReaccountSeg(const SentSeg& seg, UInt32 old_sacked,
                                  Byte old_lost, Byte old_is_retrans) noexcept;
            /**
             * @brief Kernel interval_to_edt in MICROSECONDS: how long until
             *        the pacing queue drains (tp->tcp_wstamp_ns equivalent,
             *        i.e. pacing_deadline_ - now, clamped at 0). Fed into
             *        RateSample.pacing_edt_us so KCC's
             *        kcc_packets_in_net_at_edt can credit bw*interval.
             */
            UInt32 PacingEdtUs(TimePoint now) const noexcept;
            /**
             * @brief Emits one cumulative rate sample (kernel tcp_rate_gen).
             *        Shared by the cumulative-ACK path and the SACK/DSACK
             *        dup-ACK path: the kernel samples EVERY ACK, so a dup-ACK
             *        that only advanced SACK/DSACK delivery must report too.
             */
            void EmitRateSample(TimePoint now, UInt32 acked, UInt32 rtt_sample,
                                UInt64 prior_in_flight_bytes, UInt32 ack) noexcept;
            void RetransmitEarliestMissing(TimePoint now, const TcpOpts* opts) noexcept;
            /**
             * @brief Processes peer data arriving in a closing state
             *        (FIN-WAIT-1/2, CLOSE-WAIT): deliver, reassemble
             *        out-of-order, re-ACK.
             * @return true when the peer's FIN was consumed by this call
             *         (in-order pure FIN, or a buffered out-of-order FIN
             *         whose gap filled) - the closing-state caller must
             *         then advance the state machine (RFC 793), otherwise
             *         an ACKed-but-untransitioned FIN skips 2MSL.
             */
            bool ProcessClosingData(const Byte* payload, UInt32 payload_len, UInt32 seq,
                                    bool has_fin, TimePoint now, UInt32 ts_val = 0) noexcept;
            void CutCwnd() noexcept;
            /**
             * @brief Kernel tcp_end_cwnd_reduction: close a cwnd-reduction
             *        episode (CWR or Recovery). Honours the cong_control early
             *        return, the TCP_INFINITE_SSTHRESH sentinel guard and the
             *        CWR/undo_marker condition, then dispatches
             *        kCaEventCompleteCwr.
             */
            void EndCwndReduction() noexcept;
            /**
             * @brief Sets the kernel icsk_ca_state mirror (0=Open, 3=Recovery,
             *        4=Loss) and forwards it to the CC set_state hook when the
             *        state actually changes.
             */
            void SetCaState(Byte new_state) noexcept;
            /**
             * @brief Kernel tcp_may_undo: may the current episode be undone?
             *        Batch 1: undo_marker_ only. Batch 2 (D05) adds
             *        undo_retrans_ and the RFC 3522 "packet delayed" test.
             */
            bool TcpMayUndo(const TcpOpts* opts) noexcept;
            /**
             * @brief Kernel tcp_rate_check_app_limited equivalent, called at
             *        the application send entry BEFORE consuming new data:
             *        while the sender has less than one MSS pending, the
             *        window is not full and nothing is marked lost, latch
             *        app_limited = delivered+inflight (1 when zero).  A
             *        non-matching call never clears an existing marker (the
             *        marker is cleared only when delivered passes it).
             */
            void MaybeMarkAppLimited(UInt32 inflight, TimePoint now) noexcept;
            void MarkPoolLimited(UInt32 inflight) noexcept;
            /**
             * @brief Kernel tcp_rate_gen's app-limited clear
             *        (tcp_rate_66.c:123-125): runs on EVERY ACK, cumulative
             *        and duplicate alike. after() comparison in the PACKET
             *        domain (marker = delivered_pkts watermark).
             */
            void ClearAppLimitedMarker() noexcept;
            /**
             * @brief Dispatches kCaEventTxStart when a data segment is about
             *        to leave an empty pipe (kernel CA_EVENT_TX_START).
             *        The CC implementation decides whether the connection is
             *        app-limited.  A rate change invalidates the pacing
             *        deadline (the caller may immediately re-arm it).
             */
            void NotifyTxStart(bool pipe_empty) noexcept;
            void NotifyStateChanged() noexcept;
            void MaybeFinishClose(TimePoint now) noexcept;
            static TimePoint NowUs() noexcept;
            /**
             * @brief Binds the TFO cookie to the full (client, server)
             *        endpoint triple (client IP, server IP, server port).
             *        A cookie learned on one listener cannot be replayed on
             *        another (the client IP is unchanged but the server port
             *        differs). XOR-folds the 4 address words together with
             *        the server port so both endpoints influence the hash.
             */
            void TfoBoundAddr(UInt32 out[4]) const noexcept {
                for (UInt32 i = 0; i < 4; ++i) {
                    out[i] = remote_.addr[i] ^ local_.addr[i];
                }
                out[0] ^= local_.port;
            }

            TcpState    state_;
            Endpoint    local_;
            Endpoint    remote_;
            UInt32      iss_      = 0;
            UInt32      irs_      = 0;
            UInt32      snd_una_  = 0;
            UInt32      snd_nxt_  = 0;
            UInt32      rcv_nxt_  = 0;
            UInt32      rcv_wnd_  = 65535;
            UInt32      snd_wnd_  = 65535;
            UInt32      snd_wl1_  = 0;   /**< RFC 793 SND.WL1: ack of last window update */
            UInt32      snd_wl2_  = 0;   /**< RFC 793 SND.WL2: seq of last window update */
            UInt32      window_   = 65535;
            UInt32      srtt_     = 0;      /**< Smoothed RTT (us) */
            UInt32      rttvar_   = 0;      /**< RTT variance (us) */
            UInt32      rto_      = 1000000; /**< RTO (us), RFC 6298 initial 1s */
            UInt32      two_msl_us_ = 120 * 1000000;  /**< 2MSL (RFC 793), default 120 s */
            UInt64      timewait_deadline_ = 0;       /**< TIME-WAIT reclamation deadline (us) */
            UInt32      persist_interval_ = 1000000;  /**< Zero-window probe interval (us) */
            UInt32      persist_base_     = 1000000;  /**< User-configured persist base (us); backoff only moves persist_interval_ */
            UInt64      persist_deadline_ = 0;        /**< Next zero-window probe time */
            UInt64      keepalive_idle_ = 0;          /**< Idle before keepalive probes (us); 0 = off */
            UInt64      keepalive_intvl_ = 75 * 1000000; /**< Keepalive probe interval (us); Linux TCP_KEEPINTVL 75 s */
            UInt32      keepalive_cnt_ = 8;           /**< Failed probes before abort */
            UInt32      keepalive_probes_ = 0;        /**< Consecutive unanswered probes */
            TimePoint   last_rx_ = 0;                 /**< Last inbound segment time (keepalive idle) */
            UInt16      orig_peer_mss_ = 0;           /**< Negotiated MSS before PMTUD reduction */
            UInt32      user_mss_ = 0;                /**< TCP_MAXSEG ceiling (0 = unset, Linux semantics) */
            UInt32      mtu_probe_interval_ = 600 * 1000000;  /**< RFC 1191 re-probe interval (us) */
            UInt64      mtu_probe_deadline_ = 0;      /**< Next MTU re-probe time */
            std::atomic<bool> timers_dirty_{true};    /**< Any timer armed / buffered sends (poll skip fast path) */
            TimePoint   rto_deadline_ = 0;
            UInt32      dup_acks_ = 0;
            UInt32      fast_retransmit_seq_ = 0;
            bool        ack_pending_ = false;
            UInt32      ack_count_ = 0;
            TimePoint   ack_deadline_ = 0;
            TimePoint   challenge_deadline_ = 0;  /**< RFC 5961 challenge-ACK window end (us) */
            UInt32      challenge_count_ = 0;     /**< Challenge ACKs sent in current window */
            TimePoint   dupack_deadline_ = 0;     /**< dup-ACK rate-limit window end (us) */
            UInt32      dupack_count_ = 0;        /**< Dup-ACKs sent in current window */
            struct OutSeg {
                std::vector<Byte> data;
                bool fin = false;  // RFC 793: the segment carried the FIN flag
                UInt32 ts_val = 0; // RFC 7323: the segment's TSval (TsRecent on drain)
            };
            bool TrimOooToFrontier() noexcept;
            std::map<UInt32, OutSeg> ooo_;       /**< Out-of-order reassembly buffer (seq -> segment) */
            UInt32      ooo_bytes_ = 0;
            std::deque<SentSeg> retrans_queue_;

            Byte        md5_key_[64];
            UInt32      md5_key_len_ = 0;
            UInt16      peer_mss_ = 1460;  /**< Peer-advertised MSS (default 1460) */
            static constexpr UInt32 kMinSndBuf = 4096;
            static constexpr UInt32 kDefaultSndBuf = 65536;  /**< 64 KiB per-conn quota */
            UInt32      snd_buf_ = kDefaultSndBuf;
            std::vector<Byte> pending_send_;  /**< App data queued while SYN/SYN+ACK is in flight (full client semantics) */
            mutable std::recursive_mutex syncobj_;  /**< Guards state changes (multi-thread safe) */
            TxSink      sink_;
            RecvCallback recv_cb_;
            std::function<void()> urgent_cb_;  /**< RFC 793 urgent-data notification */
            StateChangeCallback state_change_cb_; /**< Timer-driven state-change notify (stack-registered) */
            bool        close_pending_ = false;   /**< Close() deferred the FIN until buffered data drains */
            bool        nodelay_ = false;
            bool        quickack_ = false;  /**< TCP_QUICKACK: immediate ACKs */
            Byte        tfo_cookie_[8] = { 0 };  /**< Peer TFO cookie (RFC 7413) */
            bool        has_tfo_cookie_ = false;
            std::vector<Byte> tfo_syn_data_;  /**< Early data carried on the SYN (retransmit with it) */
            xtcp::core::TfoCookie tfo_;  /**< Server-side TFO cookie generator (RFC 7413) */
            std::function<void(const Byte*)> tfo_cb_;  /**< Notifies the stack of a learned cookie */
            UInt32      syn_retries_ = 6;   /**< TCP_SYNCNT: handshake retransmit budget */
            UInt32      syn_retry_count_ = 0;/**< Consecutive unanswered SYN/SYN+ACK retransmits */
            UInt32      syn_rto_ = 0;   /**< Handshake retransmit backoff (us); 0 = base rto_ */
            UInt32      fin_rto_ = 0;   /**< FIN retransmit backoff (us); 0 = base rto_ */
            UInt32      finwait2_timeout_ = 60 * 1000000;  /**< Linux tcp_fin_timeout (us) */
            UInt64      finwait2_deadline_ = 0;            /**< FIN-WAIT-2 reclamation time */
            bool        ecn_requested_ = false;
            bool        no_sack_permitted_ = false; /**< Suppress SACK-permitted on SYN (RFC 5827 ER / tcp_sack=0 parity) */
            bool        peer_syn_sack_ = false;  /**< Peer's SYN carried SACK-permitted (RFC 2018: both sides must offer) */
            bool        ecn_active_ = false;
            bool        ecn_ce_seen_ = false; /**< RFC 3168 s6.1.3: received a CE-marked IP packet */
            bool        rcv_blocked_ = false;    /**< App backpressure: advertise window 0 (RFC 1122 s4.2.3.4) */
            TimePoint   ecn_reduce_at_ = 0;  /**< Last ECE-driven cwnd cut (RFC 3168 s6.1.2: once per RTT) */
            UInt64      user_timeout_us_ = 0; /**< TCP_USER_TIMEOUT: abort when the oldest unacked exceeds this (0 = disabled) */
            bool        cwr_pending_ = false; /**< Next data segment carries CWR (RFC 3168 s6.1.2) */
            Byte        rcv_wscale_ = 0;   /**< Our advertised window scale */
            Byte        snd_wscale_ = 0;   /**< Peer's window scale */
            XtcpConnCc  cc_;               /**< Congestion-control state (KCC by default; Reno RFC 5681 when no ops are plugged) */
            std::unique_ptr<cc::XtcpCongestionOps> cc_ops_owner_;  /**< Connection-owned hook-table copy (registry race-free) */
            const cc::XtcpCongestionOps* cc_ops_ = NULLPTR;  /**< Plugged algorithm (NULLPTR = Reno); points at cc_ops_owner_ */
            bool        fast_recovery_ = false;  /**< RFC 5681 fast recovery active */
            bool        ack_not_dup_ = false;    /**< Current ACK carries data/SYN/FIN: not a dupack (RFC 5681 s2) */
            UInt32      recover_fs_ = 0;   /**< RFC 6937 PRR: flight size at the recovery entry, PACKETS
                                                (kernel tp->recover_fs is in packets: tcp_packets_in_flight) */
            UInt32      prr_delivered_ = 0; /**< RFC 6937 PRR: PACKETS delivered during recovery
                                                 (kernel tp->prr_delivered; tcp_cwnd_reduction's
                                                 newly_acked_sacked is a packet count) */
            UInt32      prr_out_ = 0;       /**< RFC 6937 PRR: PACKETS sent during recovery
                                                 (kernel tp->prr_out) */
            bool        sack_ok_ = false;        /**< RFC 2018: peer negotiated SACK (SACK-permitted on SYN/SYN+ACK) */
            bool        timestamps_ok_ = false;  /**< RFC 7323: peer negotiated TCP timestamps (both SYNs carried TSopt) */
            bool        peer_ts_offered_ = false; /**< RFC 7323: the peer's SYN carried the TSopt */
            bool        syn_ts_offered_ = false;  /**< RFC 7323: OUR SYN/SYN+ACK carried the TSopt (both-sides rule) */
            bool        ts_enabled_ = true;      /**< RFC 7323: the stack offers timestamps on its SYNs */
            UInt32      ts_recent_ = 0;          /**< RFC 7323: TsRecent - the peer's TSval of the last in-order segment (PAWS anchor + ts_ecr source) */
            UInt32      ts_recent_stamp_ = 0;    /**< RFC 7323 s5.5: ms clock when TsRecent was stored (PAWS aging - a 24-day idle relaxes the check) */
            bool        tso_tx_ = false;         /**< TSO direct-sends enabled (backend kCapTsoTx + no qdisc) */
            UInt32      retransmit_count_ = 0;   /**< Total retransmissions (RTO + fast) */
            /**
             * @brief Kernel tp->total_retrans (PACKETS): every retransmission
             *        adds tcp_skb_pcount (tcp_output_66.c:3325). The DSACK
             *        credibility gate compares dsack_dups against THIS, not
             *        against the event counter retransmit_count_ (a single
             *        TSO retransmission is several packets).
             */
            UInt32      total_retrans_pkts_ = 0;
            /**
             * @brief Kernel tp->max_window: the largest receive window the
             *        peer has advertised (tcp_input_66.c:3596-3597,
             *        tcp_input_66.c:6409). A DSACK block larger than this is
             *        dubious and must be rejected (tcp_input_66.c:1015-1017).
             */
            UInt32      max_window_ = 0;
            UInt32      rack_losses_ = 0;        /**< RFC 8985 RACK: loss verdicts that entered recovery */
            UInt32      er_losses_ = 0;          /**< RFC 5827 Early Retransmit: ER entries that entered recovery */
            UInt32      dsack_undos_ = 0;        /**< RFC 2883 D-SACK: spurious-recovery undos */
            UInt32      dsack_left_ = 0;         /**< RFC 2883: most recent duplicate's left edge (receiver) */
            UInt32      dsack_right_ = 0;        /**< RFC 2883: most recent duplicate's right edge (receiver) */
            bool        dsack_pending_ = false;  /**< RFC 2883: a duplicate awaits the next ACK's first SACK block */
            UInt32      sack_retx_next_ = 0;     /**< Next missing range to retransmit (SACK recovery) */
            UInt32      last_retx_seq_ = 0;      /**< Last SACK-path retransmit range start (storm gate) */
            UInt32      last_retx_len_ = 0;      /**< Last SACK-path retransmit length (storm gate) */
            UInt32      dsack_retx_seq_ = 0;     /**< RFC 2883: most recent retransmitted range start (persists across ACKs) */
            UInt32      dsack_retx_len_ = 0;     /**< RFC 2883: most recent retransmitted range length (persists across ACKs) */
            UInt32      high_seq_ = 0;           /**< Kernel tp->high_seq: snd_nxt at the loss/recovery entry (recovery-end test) */
            UInt32      prior_cwnd_ = 0;         /**< Pre-recovery cwnd (spurious fast-recovery undo) */
            UInt32      prior_ssthresh_ = 0;     /**< Pre-recovery ssthresh (spurious fast-recovery undo) */
            bool        undo_marker_ = false;    /**< No-SACK fast-recovery entry: undo candidate */
            /**
             * @brief Kernel tp->undo_retrans: retransmissions still in flight
             *        when the episode was entered, decremented as their ACKs
             *        arrive; -1 = "nothing retransmitted" (kernel tcp_init_undo
             *        uses `retrans_out ?: -1`). Gates tcp_may_undo together with
             *        undo_marker_. Batch 1 only writes it (no reader yet);
             *        batch 2 (D05) wires the predicate.
             */
            Int32       undo_retrans_ = -1;
            /**
             * @brief Kernel `tp->undo_marker == 0` as seen by
             *        tcp_end_cwnd_reduction (tcp_input.c:2676-2680): has THIS
             *        episode's window already been restored by an undo?
             *
             * The port's `undo_marker_` cannot carry that meaning: the SACK
             * entry sets it false (a SACK-confirmed loss never undoes), which
             * would make the kernel's `state == CWR || undo_marker` guard false
             * on a plain Recovery exit and skip the `cwnd = snd_ssthresh`
             * collapse (audit review batch1, defect 2). This flag is true
             * whenever the current episode has NOT been undone yet, so the
             * guard is `2 == ca_state || !episode_undone_`.
             *
             * Set false at every episode entry (CutCwnd covers RTO/RACK/dup-ACK,
             * plus the ECN CWR entry); set true at every undo site (DSACK,
             * Eifel, recovery-exit undo, held-episode undo) - the kernel clears
             * undo_marker in tcp_undo_cwnd_reduction (tcp_input.c:2526).
             */
            bool        episode_undone_ = true;
            UInt32      rto_ts_val_ = 0;         /**< RFC 3522 Eifel: TSval of the last data retransmission */

            bool        rto_pending_ = false;    /**< RFC 3522 Eifel: an RTO retransmission awaits its ACK */
            /**
             * @brief Kernel icsk_retransmits: consecutive RTO firings on the
             *        SAME recovery window. tcp_enter_loss only recomputes
             *        ssthresh/prior_* when this is 0 (tcp_input_66.c:2165-2173
             *        `state == TCP_CA_Loss && !icsk_retransmits`), so a second
             *        timeout inside one window must not halve the threshold
             *        again. Cleared whenever an ACK clears retransmission
             *        state (kernel tcp_clear_retrans).
             */
            UInt32      icsk_retransmits_ = 0;
            /**
             * @brief Kernel tp->retrans_stamp: the TSval of the FIRST
             *        retransmission of the current episode. Successive
             *        retransmissions must NOT advance it (kernel comment
             *        tcp_input.c:2454-2457). Batch 2 (D03) owns it.
             */
            UInt32      retrans_stamp_ts_ = 0;
            /**
             * @brief Sequence end of the segment the last RTO retransmitted;
             *        a cumulative ACK reaching it answers the "spurious?"
             *        question even without TSopt. Batch 2 (D04) owns it.
             */
            UInt32      rto_retx_end_ = 0;
            TimePoint   tlp_deadline_ = 0;       /**< Tail-loss probe deadline (RFC 8985 TLP) */
            bool        tlp_armed_ = false;      /**< A TLP probe is pending */
            TimePoint   first_outstanding_ = 0;  /**< Send time of the oldest unacked segment (TCP_USER_TIMEOUT anchor; immune to the Karn sent_at clear) */
            UInt32      rack_seq_ = 0;           /**< RFC 8985 RACK: seq of the most recently delivered segment */
            TimePoint   rack_time_ = 0;          /**< RACK: send time of the most recently delivered segment */
            UInt32      rack_reo_wnd_ = 0;       /**< RACK: reorder window (us); shrinks toward min-RTT/4 */
            TimePoint   pacing_deadline_ = 0;    /**< Next allowed send time (pacing, bytes/sec) */
            TimePoint   last_rate_sample_ = 0;   /**< Last rate-sample time (for interval_us) */
            UInt64      last_delivered_ = 0;     /**< cc_.delivered at the last emitted rate sample (delivered-delta base) */
            UInt64      last_delivered_pkts_ = 0; /**< cc_.delivered_pkts at the last emitted sample (packet-domain base) */
            UInt32      dsack_dups_ = 0;         /**< Kernel tp->dsack_dups (DSACK segment counter) */
            UInt64      batch_prior_delivered_ = 0; /**< max SentSeg.sent_delivered popped since the last emitted sample */
            UInt64  batch_prior_delivered_pkts_ = 0; /**< max SentSeg.sent_delivered_pkts popped since the last emitted sample */
            /** @brief Kernel tp->lost_out (PACKETS): segments marked lost
             *         (per-seg SentSeg.lost) and not yet delivered. */
            UInt32  lost_out_pkts_ = 0;
            /** @brief Kernel tp->retrans_out (PACKETS): retransmitted
             *         segments still in flight. */
            UInt32  retrans_out_pkts_ = 0;
            /**
             * @brief Incremental BYTE sums over retrans_queue_, maintained at
             *        every mutation so PipeInFlightBytes() is O(1).
             *
             * The kernel derives tcp_packets_in_flight() from O(1) counters
             * (packets_out/sacked_out/lost_out/retrans_out), while a queue walk
             * costs ~1.6 ns per queued segment: at a 100 Gbps BDP (~1.25 MB,
             * ~850 segments) one walk per ACK is ~1.3 us of pure overhead.
             * Every mutation of seg.sacked / seg.lost / seg.retries must update
             * these alongside, and queue insert/erase must add/subtract the
             * whole segment.
             */
            UInt32  pipe_sacked_bytes_ = 0;   /**< sum of seg.sacked */
            UInt32  pipe_lost_bytes_ = 0;     /**< sum of (len - sacked) for LOST segs */
            UInt32  pipe_retrans_bytes_ = 0;  /**< sum of (len - sacked) for retried segs */
            Byte        batch_app_limited_ = 0;     /**< app-limited snapshot of the newest popped segment */
            bool        batch_retrans_ = false;     /**< any segment popped by the CURRENT ACK was retransmitted */
            bool        last_ack_delayed_ = false;  /**< current ACK looks like a delayed ACK (kernel flag) */
            buf::TxWaiter tx_waiter_;
        };

        /**
         * @brief Passive listener with SYN queue.
         */
        class TcpListener {
        public:
            TcpListener(const Endpoint& local, UInt32 backlog, TxSink sink) noexcept;
            virtual ~TcpListener() noexcept;

            /**
             * @brief Handles a SYN addressed to the listener.
             * @param data Segment bytes.
             * @param len  Segment length.
             * @param remote Source endpoint.
             * @return True when the SYN was accepted.
             */
            bool OnSyn(const Byte* data, UInt32 len, const Endpoint& remote) noexcept;
            /**
             * @brief Accepts a completed handshake (ACK arriving after
             *        SYN+ACK), moving the flow to Established.
             * @param data Segment bytes.
             * @param len  Segment length.
             * @param remote Source endpoint.
             */
            void OnSynAck(const Byte* data, UInt32 len, const Endpoint& remote) noexcept;
            /**
             * @brief Number of pending handshakes.
             */
            UInt32 Pending() const noexcept { return pending_; }
            /**
             * @brief Configures the receive-buffer capacity advertised in the
             *        listener's SYN+ACK (default 0 = the 65535 protocol
             *        default, matching the pre-config legacy behavior).
             */
            void SetRcvBuf(UInt32 bytes) noexcept { rcv_buf_ = bytes; }

        private:
            struct SynEntry {
                Endpoint remote;
                UInt32   iss = 0;
                UInt64   created_us = 0;  /**< SYN arrival tick (stale-entry expiry) */
            };

            Endpoint    local_;
            UInt32      backlog_ = 0;
            UInt32      pending_ = 0;
            UInt32      next_iss_ = 0;
            UInt32      rcv_buf_ = 0;  /**< Advertised receive capacity for the SYN+ACK (0 = 65535 default) */
            SynEntry*   syn_queue_ = NULLPTR;
            TxSink      sink_;
        };
    }
}
#include <chrono>





