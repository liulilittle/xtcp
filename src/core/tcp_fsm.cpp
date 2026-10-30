/**
 * @file tcp_fsm.cpp
 * @brief TCP minimal state machine (RFC 793), RST validation (RFC 5961),
 *        keepalive probe response (RFC 1122).
 */

#include <xtcp/core/tcp.h>
#include <xtcp/core/md5.h>

#if defined(XTCP_X86)
    #if defined(_MSC_VER)
        #include <intrin.h>
        #include <immintrin.h>
    #elif defined(__GNUC__) || defined(__clang__)
        #include <immintrin.h>
    #endif
#endif
#if defined(XTCP_ARM) && defined(__ARM_NEON)
    #include <arm_neon.h>
#endif
#include <xtcp/core/ip.h>
#include <xtcp/cc/cc.h>

#include <chrono>
#include <atomic>
#include <new>

#include <algorithm>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace xtcp {
    namespace core {
        namespace {
            constexpr UInt32 kMaxRto = 60 * 1000000;

            /**
             * @brief Kernel tcp_skb_pcount: packets a segment represents.
             *        tcp_set_skb_tso_segs (tcp_output_v66.c:1457-1464) uses 1
             *        for len <= mss and DIV_ROUND_UP(len, mss) above it.
             */
            inline UInt32 PktCount(UInt32 len, UInt32 mss) noexcept {
                if (0 == mss || len <= mss) {
                    return 1;
                }
                return (len + mss - 1) / mss;
            }

            // Monotonic IPv4 Identification (RFC 6864). A constant id of 0
            // makes a downstream reassembler merge all in-flight datagrams of
            // one flow (key: src,dst,proto,id) into a single set. Linux
            // increments per packet (inet_getid); we mirror that with a
            // per-packet atomic counter (relaxed is sufficient: ids only need
            // uniqueness, not ordering).
            std::atomic<UInt16> g_ip_id{0};

            inline UInt16 NextIpv4Id() noexcept {
                return static_cast<UInt16>(g_ip_id.fetch_add(1, std::memory_order_relaxed) + 1);
            }

            constexpr Byte kProtoTcp = 6;
            constexpr UInt32 kDefaultWindow = 65535;
            constexpr UInt32 kMaxDataRetries = 15;  // Linux tcp_retries2 equivalent
            constexpr UInt32 kDelayedAckMs = 40;  // RFC 1122 delayed-ACK timer
            // MSS carried in our SYN/SYN+ACK MSS option (0x05B4); the upper
            // bound of the kernel's icsk_ack.rcv_mss estimate (advmss).
            constexpr UInt32 kAdvertisedMss = 1460;
            // RFC 7323 s5.5: after this much idle time (24 days) the peer's
            // millisecond clock may have wrapped - the PAWS check is relaxed
            // (the sequence-number checks still bound the segment). Linux:
            // TCP_PAWS_24DAYS.
            constexpr UInt32 kPawsMaxIdleMs = 24 * 24 * 3600 * 1000u;
            constexpr UInt32 kOooLimit = 65536;    // Minimum out-of-order buffer cap (bytes)

            // The out-of-order buffer holds receive memory. A configured
            // receive window (SetRcvBuf) larger than the legacy kOooLimit must
            // NOT be undermined by eviction at the fixed 64KB mark - the
            // advertised window promises window_ - ooo_bytes_ free capacity,
            // so the buffering must honor the same budget (default: 65535
            // window -> the legacy 65536 cap, unchanged). kOooLimit is the
            // floor (the legacy 65536 cap); a configured window larger than
            // it raises the effective cap (cap = max(rcv_wnd, kOooLimit)).
            inline UInt32 OooCapacity(UInt32 rcv_wnd) noexcept {
                return (rcv_wnd > kOooLimit) ? rcv_wnd : kOooLimit;
            }

            inline UInt16 Load16(const Byte* p) noexcept {
                return static_cast<UInt16>((static_cast<UInt16>(p[0]) << 8) | p[1]);
            }
            inline UInt32 Load32(const Byte* p) noexcept {
                return (static_cast<UInt32>(p[0]) << 24) |
                       (static_cast<UInt32>(p[1]) << 16) |
                       (static_cast<UInt32>(p[2]) << 8)  |
                       static_cast<UInt32>(p[3]);
            }

            inline UInt16 ChecksumCombine(UInt16 a, UInt16 b) noexcept {
                UInt32 sum = (static_cast<UInt32>(~a) & 0xFFFF) + (static_cast<UInt32>(~b) & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                return static_cast<UInt16>(~sum & 0xFFFF);
            }

            // Big-endian word loads for the RFC 1071 accumulation. A single
            // native memcpy gives one load/store instruction; on little-endian
            // hosts the word is byte-swapped to match the on-wire byte order
            // (compiles to bswap), on big-endian hosts it is a no-op.
            inline UInt32 Byteswap32(UInt32 w) noexcept {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
                return w;
#else
                return ((w & 0xFFu) << 24) | ((w & 0xFF00u) << 8) |
                       ((w >> 8) & 0xFF00u) | ((w >> 24) & 0xFFu);
#endif
            }
            inline UInt16 Byteswap16(UInt16 w) noexcept {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
                return w;
#else
                return static_cast<UInt16>((w >> 8) | (w << 8));
#endif
            }

#if defined(XTCP_HAS_SSSE3_CODE)
            /**
             * @brief Fused copy + RFC 1071 checksum (vectorized path, SSSE3).
             *        Bit-identical result to the scalar accumulation: the
             *        bytes are copied verbatim and the checksum accumulates
             *        the same 16-bit big-endian words (pshufb-reversed 16-byte
             *        chunks zero-extended into 32-bit lanes - addition is
             *        commutative, so the fold matches exactly).
             */
            XTCP_TARGET_SSSE3 inline UInt16 CopyAndChecksumSimd(Byte* dst, const Byte* src, UInt32 len) noexcept {
                __m128i acc_lo = _mm_setzero_si128();
                __m128i acc_hi = _mm_setzero_si128();
                static const __m128i kRev16 = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
                UInt64 sum = 0;
                UInt32 n = len;
                while (32 <= n) {
                    __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src));
                    __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src + 16));
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(dst), x);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(dst + 16), y);
                    x = _mm_shuffle_epi8(x, kRev16);
                    y = _mm_shuffle_epi8(y, kRev16);
                    acc_lo = _mm_add_epi32(acc_lo, _mm_unpacklo_epi16(x, _mm_setzero_si128()));
                    acc_lo = _mm_add_epi32(acc_lo, _mm_unpackhi_epi16(x, _mm_setzero_si128()));
                    acc_hi = _mm_add_epi32(acc_hi, _mm_unpacklo_epi16(y, _mm_setzero_si128()));
                    acc_hi = _mm_add_epi32(acc_hi, _mm_unpackhi_epi16(y, _mm_setzero_si128()));
                    src += 32;
                    dst += 32;
                    n -= 32;
                    if (0 == (n & 0x3FFF)) {
                        alignas(16) UInt32 lo[4];
                        alignas(16) UInt32 hi[4];
                        _mm_storeu_si128(reinterpret_cast<__m128i*>(lo), acc_lo);
                        _mm_storeu_si128(reinterpret_cast<__m128i*>(hi), acc_hi);
                        for (UInt32 i = 0; i < 4; ++i) {
                            sum += static_cast<UInt64>(lo[i]) + hi[i];
                        }
                        acc_lo = _mm_setzero_si128();
                        acc_hi = _mm_setzero_si128();
                    }
                }
                alignas(16) UInt32 lo[4];
                alignas(16) UInt32 hi[4];
                _mm_storeu_si128(reinterpret_cast<__m128i*>(lo), acc_lo);
                _mm_storeu_si128(reinterpret_cast<__m128i*>(hi), acc_hi);
                for (UInt32 i = 0; i < 4; ++i) {
                    sum += static_cast<UInt64>(lo[i]) + hi[i];
                }
                while (4 <= n) {
                    UInt32 w;
                    std::memcpy(&w, src, 4);
                    sum += Byteswap32(w);
                    std::memcpy(dst, &w, 4);
                    src += 4;
                    dst += 4;
                    n -= 4;
                }
                while (1 < n) {
                    UInt16 w;
                    std::memcpy(&w, src, 2);
                    sum += Byteswap16(w);
                    std::memcpy(dst, &w, 2);
                    src += 2;
                    dst += 2;
                    n -= 2;
                }
                if (0 < n) {
                    dst[0] = src[0];
                    sum += static_cast<UInt16>(static_cast<UInt16>(src[0]) << 8);
                }
                while (0 != (sum >> 16)) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                return static_cast<UInt16>(~sum & 0xFFFF);
            }
#endif  // XTCP_X86 && SSSE3: CopyAndChecksumSimd

#if defined(XTCP_HAS_AVX2_CODE)
            /**
             * @brief Fused copy + RFC 1071 checksum (AVX2, 256-bit).
             *
             * Same accumulation rule as CopyAndChecksumSimd:
             * `_mm256_shuffle_epi8` reverses the 16 bytes inside each 128-bit
             * lane (word order inside a lane does not matter - addition is
             * commutative and associative), then `unpack*_epi16` zero-extends
             * the words into 32-bit lanes so a byte carry can never cross a
             * word boundary. 64 bytes per iteration with two independent
             * accumulator chains; the periodic drain (every 16 KiB, as in the
             * SSSE3 kernel) keeps every lane far below 2^32.
             */
            XTCP_TARGET_AVX2 inline UInt16 CopyAndChecksumAvx2(Byte* dst, const Byte* src, UInt32 len) noexcept {
                const __m128i rev128 = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
                const __m256i rev = _mm256_broadcastsi128_si256(rev128);
                const __m256i zero = _mm256_setzero_si256();
                __m256i acc0 = _mm256_setzero_si256();
                __m256i acc1 = _mm256_setzero_si256();
                UInt64 sum = 0;
                UInt32 n = len;
                while (64 <= n) {
                    __m256i x = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src));
                    __m256i y = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + 32));
                    _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst), x);
                    _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + 32), y);
                    x = _mm256_shuffle_epi8(x, rev);
                    y = _mm256_shuffle_epi8(y, rev);
                    acc0 = _mm256_add_epi32(acc0, _mm256_unpacklo_epi16(x, zero));
                    acc0 = _mm256_add_epi32(acc0, _mm256_unpackhi_epi16(x, zero));
                    acc1 = _mm256_add_epi32(acc1, _mm256_unpacklo_epi16(y, zero));
                    acc1 = _mm256_add_epi32(acc1, _mm256_unpackhi_epi16(y, zero));
                    src += 64;
                    dst += 64;
                    n -= 64;
                    if (0 == (n & 0x3FFF)) {
                        alignas(32) UInt32 lanes[8];
                        _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), acc0);
                        for (UInt32 i = 0; i < 8; ++i) {
                            sum += lanes[i];
                        }
                        _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), acc1);
                        for (UInt32 i = 0; i < 8; ++i) {
                            sum += lanes[i];
                        }
                        acc0 = _mm256_setzero_si256();
                        acc1 = _mm256_setzero_si256();
                    }
                }
                alignas(32) UInt32 lanes_end[8];
                _mm256_store_si256(reinterpret_cast<__m256i*>(lanes_end), acc0);
                for (UInt32 i = 0; i < 8; ++i) {
                    sum += lanes_end[i];
                }
                _mm256_store_si256(reinterpret_cast<__m256i*>(lanes_end), acc1);
                for (UInt32 i = 0; i < 8; ++i) {
                    sum += lanes_end[i];
                }
                while (4 <= n) {
                    UInt32 w;
                    std::memcpy(&w, src, 4);
                    sum += Byteswap32(w);
                    std::memcpy(dst, &w, 4);
                    src += 4;
                    dst += 4;
                    n -= 4;
                }
                while (1 < n) {
                    UInt16 w;
                    std::memcpy(&w, src, 2);
                    sum += Byteswap16(w);
                    std::memcpy(dst, &w, 2);
                    src += 2;
                    dst += 2;
                    n -= 2;
                }
                if (0 < n) {
                    dst[0] = src[0];
                    sum += static_cast<UInt16>(static_cast<UInt16>(src[0]) << 8);
                }
                while (0 != (sum >> 16)) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                return static_cast<UInt16>(~sum & 0xFFFF);
            }
#endif  // XTCP_HAS_AVX2_CODE: CopyAndChecksumAvx2


#if defined(XTCP_ARM) && defined(__ARM_NEON)
            /**
             * @brief Fused copy + RFC 1071 checksum (vectorized path, ARM NEON).
             *        Bit-identical result to the scalar accumulation: the
             *        bytes are copied verbatim and the checksum accumulates
             *        the same 16-bit big-endian words (vrev16q reverses bytes
             *        within each 16-byte chunk, zero-extended into 32-bit
             *        lanes for accumulation - addition is commutative, so
             *        the fold matches exactly).
             */
            inline UInt16 CopyAndChecksumNeon(Byte* dst, const Byte* src, UInt32 len) noexcept {
                uint32x4_t acc_lo = vdupq_n_u32(0);
                uint32x4_t acc_hi = vdupq_n_u32(0);
                UInt64 sum = 0;
                UInt32 n = len;
                while (32 <= n) {
                    uint8x16_t x = vld1q_u8(src);
                    uint8x16_t y = vld1q_u8(src + 16);
                    vst1q_u8(dst, x);
                    vst1q_u8(dst + 16, y);
                    // Reverse bytes within each 16-bit word for big-endian accumulation
                    x = vrev16q_u8(x);
                    y = vrev16q_u8(y);
                    // Unpack to 32-bit lanes and accumulate (vmovl_u16
                    // zero-extends each big-endian 16-bit word into a 32-bit
                    // lane; vaddq_u32 accumulates lane-wise).
                    acc_lo = vaddq_u32(acc_lo, vmovl_u16(vget_low_u16(vreinterpretq_u16_u8(x))));
                    acc_lo = vaddq_u32(acc_lo, vmovl_u16(vget_high_u16(vreinterpretq_u16_u8(x))));
                    acc_hi = vaddq_u32(acc_hi, vmovl_u16(vget_low_u16(vreinterpretq_u16_u8(y))));
                    acc_hi = vaddq_u32(acc_hi, vmovl_u16(vget_high_u16(vreinterpretq_u16_u8(y))));
                    src += 32;
                    dst += 32;
                    n -= 32;
                    if (0 == (n & 0x3FFF)) {
                        alignas(16) UInt32 lo[4];
                        alignas(16) UInt32 hi[4];
                        vst1q_u32(lo, acc_lo);
                        vst1q_u32(hi, acc_hi);
                        for (UInt32 i = 0; i < 4; ++i) {
                            sum += static_cast<UInt64>(lo[i]) + hi[i];
                        }
                        acc_lo = vdupq_n_u32(0);
                        acc_hi = vdupq_n_u32(0);
                    }
                }
                alignas(16) UInt32 lo[4];
                alignas(16) UInt32 hi[4];
                vst1q_u32(lo, acc_lo);
                vst1q_u32(hi, acc_hi);
                for (UInt32 i = 0; i < 4; ++i) {
                    sum += static_cast<UInt64>(lo[i]) + hi[i];
                }
                while (4 <= n) {
                    UInt32 w;
                    std::memcpy(&w, src, 4);
                    sum += Byteswap32(w);
                    std::memcpy(dst, &w, 4);
                    src += 4;
                    dst += 4;
                    n -= 4;
                }
                while (1 < n) {
                    UInt16 w;
                    std::memcpy(&w, src, 2);
                    sum += Byteswap16(w);
                    std::memcpy(dst, &w, 2);
                    src += 2;
                    dst += 2;
                    n -= 2;
                }
                if (0 < n) {
                    dst[0] = src[0];
                    sum += static_cast<UInt16>(static_cast<UInt16>(src[0]) << 8);
                }
                while (0 != (sum >> 16)) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                return static_cast<UInt16>(~sum & 0xFFFF);
            }
#endif  // XTCP_ARM && __ARM_NEON: CopyAndChecksumNeon

            /**
             * @brief Copies len bytes src->dst while accumulating the RFC 1071
             *        one's-complement sum in a single pass (32-bit word
             *        accumulation, fold at the end - same arithmetic as
             *        Checksum() so the result is bit-identical). Fuses the
             *        payload copy and the TCP checksum traversal that used to
             *        read the payload twice.
             * @param md5  optional MD5 context: when non-null the source bytes
             *        are streamed into it while they are copied, so the RFC 2385
             *        digest never re-reads the payload from the packet buffer
             *        (signature connections read the payload once, not twice).
             */
            inline UInt16 CopyAndChecksum(Byte* dst, const Byte* src, UInt32 len, Md5Ctx* md5 = NULLPTR) noexcept {
#if defined(XTCP_HAS_AVX2_CODE)
                // MD5 interleaving is inherently scalar; the vectorized
                // paths serve the (common) unsigned fast path. AVX2
                // first: 32-byte lanes halve the SSSE3 loop count.
                if (NULLPTR == md5 && CpuHasAvx2()) {
                    return CopyAndChecksumAvx2(dst, src, len);
                }
#endif
#if defined(XTCP_HAS_SSSE3_CODE)
                // MD5 interleaving is inherently scalar; the vectorized path
                // serves the (common) unsigned fast path.
                if (NULLPTR == md5 && CpuHasSsse3()) {
                    return CopyAndChecksumSimd(dst, src, len);
                }
#elif defined(XTCP_ARM) && defined(__ARM_NEON)
                // MD5 interleaving is inherently scalar; the vectorized path
                // serves the (common) unsigned fast path.
                if (NULLPTR == md5) {
                    return CopyAndChecksumNeon(dst, src, len);
                }
#else
                (void)md5;
#endif
                UInt64 sum = 0;
                UInt32 n = len;
                while (4 <= n) {
                    UInt32 w;
                    std::memcpy(&w, src, 4);
                    sum += Byteswap32(w);
                    std::memcpy(dst, &w, 4);
                    if (NULLPTR != md5) {
                        Md5Update(*md5, src, 4);
                    }
                    src += 4;
                    dst += 4;
                    n -= 4;
                }
                while (1 < n) {
                    UInt16 w;
                    std::memcpy(&w, src, 2);
                    sum += Byteswap16(w);
                    std::memcpy(dst, &w, 2);
                    if (NULLPTR != md5) {
                        Md5Update(*md5, src, 2);
                    }
                    src += 2;
                    dst += 2;
                    n -= 2;
                }
                if (0 < n) {
                    dst[0] = src[0];
                    sum += static_cast<UInt16>(static_cast<UInt16>(src[0]) << 8);
                    if (NULLPTR != md5) {
                        Md5Update(*md5, src, 1);
                    }
                }
                while (0 != (sum >> 16)) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                return static_cast<UInt16>(~sum & 0xFFFF);
            }

            /**
             * @brief Builds a complete IPv4+TCP packet.
             * @return Packet ready to transmit; empty on allocation failure.
             */
            buf::BufRef BuildSegmentPacket(const Endpoint& local, const Endpoint& remote, UInt32 seq, UInt32 ack,
                                           UInt16 flags, const Byte* payload, UInt32 payload_len,
                                           UInt16 window, Byte wscale = 0,
                                           const Byte* md5_key = NULLPTR, UInt32 md5_key_len = 0,
                                           const UInt32* sack_blocks = NULLPTR, Byte sack_blocks_count = 0,
                                           const Byte* tfo_cookie = NULLPTR,
                                           bool mark_ect = false,
                                           bool include_ts = false, UInt32 ts_val = 0, UInt32 ts_ecr = 0,
                                           bool no_sack_permitted = false) noexcept {
                const bool is_v6 = (6 == remote.family);
                // SYN options: MSS (RFC 879) + SACK-permitted (RFC 2018) +
                // window scale (RFC 7323) + TFO cookie (RFC 7413);
                // TCP-MD5 (RFC 2385) on all segments. TFO and MD5 are
                // mutually exclusive (the option area would overflow).
                const bool include_wscale = (0 != (flags & kFlagSyn));
                const bool include_mss = (0 != (flags & kFlagSyn));
                // SACK-permitted (RFC 2018) is offered on SYNs by default;
                // kTcpNoSackPermitted suppresses it (RFC 5827 ER needs
                // SACK-less connections - RACK's sack_ok_ gate never fires).
                const bool include_sack = (0 != (flags & kFlagSyn)) && !no_sack_permitted;
                const bool include_md5 = (NULLPTR != md5_key && 0 < md5_key_len);
                const bool include_tfo = (0 != (flags & kFlagSyn)) && (NULLPTR != tfo_cookie) && !include_md5;
                // RFC 7323 timestamps: kind 8, length 10, tsval + tsecr.
                // Offered on SYNs (both sides must offer for the option to
                // activate). Once negotiated the option is carried on ACK
                // segments and RTO retransmissions (fresh TSval, RFC 7323
                // s5.3); the direct data-send and rebuild paths deliberately
                // omit it (see BuildSegmentPacket's include_ts callers) -
                // the peer's PAWS check never rejects a segment that lacks
                // the option. Never on MD5 connections (RFC 2385 needs the
                // option space and the signature must not be split by a
                // moving TSopt).
                const UInt32 syn_opt_len = (include_mss ? 4 : 0) + (include_sack ? 4 : 0) +
                                           (include_wscale ? 4 : 0) + (include_tfo ? 12 : 0) +
                                           (include_ts ? 12 : 0);
                // Data-segment SACK blocks (RFC 2018), never on a SYN.
                Byte sack_n = 0;
                UInt32 sack_opt_len = 0;
                if (!include_sack && NULLPTR != sack_blocks && 0 < sack_blocks_count) {
                    // RFC 2018 SACK shares the 40-byte TCP option space with
                    // every other option on the segment: the 12-byte TSopt
                    // (RFC 7323) and the 20-byte MD5 signature (RFC 2385).
                    // Fit as many blocks as the remaining space allows -
                    // 4 alone (2 + 32 + 2 NOP = 36), 3 with timestamps
                    // (12 + 2 + 24 + 2 NOP = 40, as Linux), 2 with MD5
                    // (20 + 2 + 16 + 2 NOP = 40). Overflowing 40 bytes makes
                    // the 4-bit data offset wrap: the peer drops the ACK.
                    const UInt32 used = syn_opt_len + (include_md5 ? 20 : 0);
                    const UInt32 room = (used < 40) ? 40 - used : 0;
                    const UInt32 fit = (room >= 2 + 8) ? (room - 2) / 8 : 0;
                    const Byte sack_cap = static_cast<Byte>(fit < 4 ? fit : 4);
                    sack_n = (sack_blocks_count > sack_cap) ? sack_cap : sack_blocks_count;
                    sack_opt_len = (0 < sack_n) ? (((2 + 8 * sack_n) + 3) & ~3u) : 0;  // NOP-padded to 4
                }
                const UInt32 md5_off = syn_opt_len + sack_opt_len;
                const UInt32 opt_len = md5_off + (include_md5 ? 20 : 0);
                const UInt32 ip_hdr_len = is_v6 ? 40 : 20;
                const UInt32 tcp_hdr_len = 20 + opt_len;
                const UInt32 total = ip_hdr_len + tcp_hdr_len + payload_len;
                buf::BufRef packet = buf::BufRef::Acquire(total);
                if (packet.IsEmpty()) {
                    return packet;
                }
                Byte* p = packet.Data();

                if (is_v6) {
                    // IPv6 header (RFC 8200).
                    p[0] = 0x60;
                    p[1] = mark_ect ? 0x20 : 0x00;  // ECT(1) ('10') in traffic-class bits
                    p[2] = 0x00;
                    p[3] = 0x00;  // payload length
                    p[4] = static_cast<Byte>((tcp_hdr_len + payload_len) >> 8);
                    p[5] = static_cast<Byte>((tcp_hdr_len + payload_len) & 0xFF);
                    p[6] = kProtoTcp;  // next header
                    p[7] = 64;         // hop limit
                    for (UInt32 i = 0; i < 4; ++i) {
                        const UInt32 src = local.addr[i];
                        const UInt32 dst = remote.addr[i];
                        Byte* sp = p + 8 + i * 4;
                        Byte* dp = p + 24 + i * 4;
                        sp[0] = static_cast<Byte>(src >> 24);
                        sp[1] = static_cast<Byte>(src >> 16);
                        sp[2] = static_cast<Byte>(src >> 8);
                        sp[3] = static_cast<Byte>(src & 0xFF);
                        dp[0] = static_cast<Byte>(dst >> 24);
                        dp[1] = static_cast<Byte>(dst >> 16);
                        dp[2] = static_cast<Byte>(dst >> 8);
                        dp[3] = static_cast<Byte>(dst & 0xFF);
                    }
                } else {
                    // IPv4 header.
                    p[0] = 0x45;
                    p[1] = mark_ect ? 0x02 : 0x00;  // ECT(1) ('10') in ECN field (low 2 bits)
                    p[2] = static_cast<Byte>(total >> 8);
                    p[3] = static_cast<Byte>(total & 0xFF);
                    const UInt16 ip_id = NextIpv4Id();
                    p[4] = static_cast<Byte>(ip_id >> 8);
                    p[5] = static_cast<Byte>(ip_id & 0xFF);
                    p[6] = 0x40;  // DF
                    p[7] = 0x00;
                    p[8] = 64;    // TTL
                    p[9] = kProtoTcp;
                    p[10] = 0x00;
                    p[11] = 0x00;  // checksum placeholder
                    p[12] = static_cast<Byte>(local.addr[0] >> 24);
                    p[13] = static_cast<Byte>(local.addr[0] >> 16);
                    p[14] = static_cast<Byte>(local.addr[0] >> 8);
                    p[15] = static_cast<Byte>(local.addr[0] & 0xFF);
                    p[16] = static_cast<Byte>(remote.addr[0] >> 24);
                    p[17] = static_cast<Byte>(remote.addr[0] >> 16);
                    p[18] = static_cast<Byte>(remote.addr[0] >> 8);
                    p[19] = static_cast<Byte>(remote.addr[0] & 0xFF);
                    const UInt16 ip_sum = Checksum(p, 20);
                    p[10] = static_cast<Byte>(ip_sum >> 8);
                    p[11] = static_cast<Byte>(ip_sum & 0xFF);
                }

                // TCP header.
                Byte* t = p + ip_hdr_len;
                t[0] = static_cast<Byte>(local.port >> 8);    // sport
                t[1] = static_cast<Byte>(local.port & 0xFF);
                t[2] = static_cast<Byte>(remote.port >> 8);   // dport
                t[3] = static_cast<Byte>(remote.port & 0xFF);
                t[4] = static_cast<Byte>(seq >> 24);
                t[5] = static_cast<Byte>(seq >> 16);
                t[6] = static_cast<Byte>(seq >> 8);
                t[7] = static_cast<Byte>(seq & 0xFF);
                t[8] = static_cast<Byte>(ack >> 24);
                t[9] = static_cast<Byte>(ack >> 16);
                t[10] = static_cast<Byte>(ack >> 8);
                t[11] = static_cast<Byte>(ack & 0xFF);
                // Data offset: 5 + options (4-bit field, high nibble).
                t[12] = static_cast<Byte>(((20 + opt_len) >> 2) << 4);
                t[13] = static_cast<Byte>(((flags & kFlagFin) ? 0x01 : 0x00) |
                                         ((flags & kFlagSyn) ? 0x02 : 0x00) |
                                         ((flags & kFlagRst) ? 0x04 : 0x00) |
                                         ((flags & kFlagPsh) ? 0x08 : 0x00) |
                                         ((flags & kFlagAck) ? 0x10 : 0x00) |
                                         ((flags & kFlagUrg) ? 0x20 : 0x00) |
                                         ((flags & kFlagEce) ? 0x40 : 0x00) |
                                         ((flags & kFlagCwr) ? 0x80 : 0x00));
                t[14] = static_cast<Byte>(window >> 8);
                t[15] = static_cast<Byte>(window & 0xFF);
                t[16] = 0x00;  // checksum placeholder
                t[17] = 0x00;
                t[18] = 0x00;
                t[19] = 0x00;  // urgent pointer
                if (include_mss) {
                    t[20] = 2;       // kind: MSS
                    t[21] = 4;       // length
                    t[22] = 0x05;    // MSS 1460
                    t[23] = 0xB4;
                }
                if (include_sack) {
                    t[24] = 4;       // kind: SACK-permitted
                    t[25] = 2;
                    t[26] = 1;       // NOP
                    t[27] = 1;       // NOP
                }
                if (include_wscale) {
                    t[28] = 3;       // kind: WSOPT
                    t[29] = 3;       // length
                    t[30] = wscale;  // value (0-14)
                    t[31] = 1;       // NOP padding
                }
                // TFO cookie (RFC 7413): kind 34, length 10, 8-byte cookie
                // (kTfoCookieLen; 2 + 8 + 2 NOP = 12 bytes).
                if (include_tfo) {
                    t[32] = 34;
                    t[33] = 10;
                    for (UInt32 i = 0; i < 8; ++i) {
                        t[34 + i] = tfo_cookie[i];
                    }
                    t[42] = 1;  // NOP padding
                    t[43] = 1;
                }
                // RFC 7323 timestamps (kind 8, len 10): tsval + tsecr. The
                // option sits after the SYN options (the layout is
                // MSS/SACK/WS/TFO then TS), on the SYN offer and (once
                // negotiated) on ACK/RTO-retransmit segments; the direct
                // data-send paths deliberately omit it (include_ts callers).
                if (include_ts) {
                    const UInt32 ts_off = 20 + syn_opt_len - 12;
                    t[ts_off]     = 8;   // kind: TSopt
                    t[ts_off + 1] = 10;  // length
                    t[ts_off + 2] = static_cast<Byte>(ts_val >> 24);
                    t[ts_off + 3] = static_cast<Byte>(ts_val >> 16);
                    t[ts_off + 4] = static_cast<Byte>(ts_val >> 8);
                    t[ts_off + 5] = static_cast<Byte>(ts_val & 0xFF);
                    t[ts_off + 6] = static_cast<Byte>(ts_ecr >> 24);
                    t[ts_off + 7] = static_cast<Byte>(ts_ecr >> 16);
                    t[ts_off + 8] = static_cast<Byte>(ts_ecr >> 8);
                    t[ts_off + 9] = static_cast<Byte>(ts_ecr & 0xFF);
                    t[ts_off + 10] = 1;  // NOP padding
                    t[ts_off + 11] = 1;
                }
                // Data-segment SACK blocks (RFC 2018): kind 5.
                if (0 < sack_n) {
                    Byte* so = t + 20 + syn_opt_len;
                    so[0] = 5;                             // kind: SACK
                    so[1] = static_cast<Byte>(2 + 8 * sack_n);  // length
                    for (Byte b = 0; b < sack_n; ++b) {
                        const UInt32 left = sack_blocks[b * 2];
                        const UInt32 right = sack_blocks[b * 2 + 1];
                        so[2 + b * 8]     = static_cast<Byte>(left >> 24);
                        so[3 + b * 8]     = static_cast<Byte>(left >> 16);
                        so[4 + b * 8]     = static_cast<Byte>(left >> 8);
                        so[5 + b * 8]     = static_cast<Byte>(left & 0xFF);
                        so[6 + b * 8]     = static_cast<Byte>(right >> 24);
                        so[7 + b * 8]     = static_cast<Byte>(right >> 16);
                        so[8 + b * 8]     = static_cast<Byte>(right >> 8);
                        so[9 + b * 8]     = static_cast<Byte>(right & 0xFF);
                    }
                    for (UInt32 pad = 2 + 8 * sack_n; pad < sack_opt_len; ++pad) {
                        so[pad] = 1;  // NOP padding
                    }
                }
                if (include_md5) {
                    // RFC 2385: kind 19, length 18, 16-byte digest (zeroed now),
                    // padded with two NOPs to a 4-byte boundary.
                    t[20 + md5_off]     = 19;  // kind: TCP-MD5
                    t[21 + md5_off]     = 18;  // length
                    for (UInt32 i = 0; i < 16; ++i) {
                        t[22 + md5_off + i] = 0;
                    }
                    t[38 + md5_off]     = 1;   // NOP
                    t[39 + md5_off]     = 1;   // NOP
                }

                // Pseudo header for both the RFC 1071 TCP checksum and the RFC
                // 2385 digest (IPv4: 12B, IPv6: 40B). Built once, before the
                // payload copy, so the MD5 digest can stream the pseudo + TCP
                // header (checksum field and MD5 option still zero) into its
                // context and then fold the payload in while it is copied.
                Byte pseudo[40];
                UInt32 pseudo_len = 0;
                if (is_v6) {
                    for (UInt32 i = 0; i < 4; ++i) {
                        const UInt32 src = local.addr[i];
                        const UInt32 dst = remote.addr[i];
                        Byte* sp = pseudo + i * 4;
                        Byte* dp = pseudo + 16 + i * 4;
                        sp[0] = static_cast<Byte>(src >> 24);
                        sp[1] = static_cast<Byte>(src >> 16);
                        sp[2] = static_cast<Byte>(src >> 8);
                        sp[3] = static_cast<Byte>(src & 0xFF);
                        dp[0] = static_cast<Byte>(dst >> 24);
                        dp[1] = static_cast<Byte>(dst >> 16);
                        dp[2] = static_cast<Byte>(dst >> 8);
                        dp[3] = static_cast<Byte>(dst & 0xFF);
                    }
                    pseudo[32] = static_cast<Byte>((tcp_hdr_len + payload_len) >> 24);
                    pseudo[33] = static_cast<Byte>((tcp_hdr_len + payload_len) >> 16);
                    pseudo[34] = static_cast<Byte>((tcp_hdr_len + payload_len) >> 8);
                    pseudo[35] = static_cast<Byte>((tcp_hdr_len + payload_len) & 0xFF);  // 32-bit length
                    pseudo[36] = 0x00;
                    pseudo[37] = 0x00;
                    pseudo[38] = 0x00;
                    pseudo[39] = kProtoTcp;
                    pseudo_len = 40;
                } else {
                    pseudo[0] = static_cast<Byte>(local.addr[0] >> 24);
                    pseudo[1] = static_cast<Byte>(local.addr[0] >> 16);
                    pseudo[2] = static_cast<Byte>(local.addr[0] >> 8);
                    pseudo[3] = static_cast<Byte>(local.addr[0] & 0xFF);
                    pseudo[4] = static_cast<Byte>(remote.addr[0] >> 24);
                    pseudo[5] = static_cast<Byte>(remote.addr[0] >> 16);
                    pseudo[6] = static_cast<Byte>(remote.addr[0] >> 8);
                    pseudo[7] = static_cast<Byte>(remote.addr[0] & 0xFF);
                    pseudo[8] = 0x00;
                    pseudo[9] = kProtoTcp;
                    pseudo[10] = static_cast<Byte>((tcp_hdr_len + payload_len) >> 8);
                    pseudo[11] = static_cast<Byte>((tcp_hdr_len + payload_len) & 0xFF);
                    pseudo_len = 12;
                }

                // TCP-MD5 (RFC 2385): stream the pseudo header and the TCP
                // header (checksum field and MD5 option are still zero here)
                // into the digest context, then feed the payload while
                // CopyAndChecksum copies it (payload read once), then fold in
                // the key. Byte stream == pseudo || header || payload || key,
                // bit-identical to the digest ComputeMd5Segment used to emit.
                Md5Ctx md5_ctx;
                if (include_md5) {
                    Md5Init(md5_ctx);
                    Md5Update(md5_ctx, pseudo, pseudo_len);
                    Md5Update(md5_ctx, t, tcp_hdr_len);
                }
                // Copy payload and fold its RFC 1071 sum into the checksum in
                // a single pass (payload is read once, not twice).
                UInt16 payload_sum = 0;
                if (0 < payload_len) {
                    payload_sum = CopyAndChecksum(t + 20 + opt_len, payload, payload_len,
                                                  include_md5 ? &md5_ctx : NULLPTR);
                }
                if (include_md5) {
                    Md5Update(md5_ctx, md5_key, md5_key_len);
                    std::uint8_t digest[16];
                    Md5Final(md5_ctx, digest);
                    for (UInt32 i = 0; i < 16; ++i) {
                        t[20 + md5_off + 2 + i] = static_cast<Byte>(digest[i]);
                    }
                }

                // TCP checksum with pseudo header: covers the real on-wire
                // bytes including the MD5 digest (checksum field still zero).
                const UInt16 pseudo_sum = Checksum(pseudo, pseudo_len);
                const UInt16 tcp_sum = Checksum(t, tcp_hdr_len);
                const UInt16 sum = ChecksumCombine(ChecksumCombine(pseudo_sum, tcp_sum), payload_sum);
                t[16] = static_cast<Byte>(sum >> 8);
                t[17] = static_cast<Byte>(sum & 0xFF);

                packet.SetLen(total);
                packet.Meta().mss = 0;
                packet.Meta().segs = 0;
                return packet;
            }

            /**
             * @brief Builds and delivers a segment to the sink.
             */
            void SendSegmentPacket(const Endpoint& local, const Endpoint& remote, UInt32 seq, UInt32 ack,
                                   UInt16 flags, const Byte* payload, UInt32 payload_len,
                                   UInt16 window, const TxSink& sink, Byte wscale = 0,
                                   const Byte* md5_key = NULLPTR, UInt32 md5_key_len = 0,
                                   const UInt32* sack_blocks = NULLPTR, Byte sack_blocks_count = 0,
                                   const Byte* tfo_cookie = NULLPTR,
                                   bool mark_ect = false,
                                   bool include_ts = false, UInt32 ts_val = 0, UInt32 ts_ecr = 0,
                                   bool no_sack_permitted = false) noexcept {
                buf::BufRef packet = BuildSegmentPacket(local, remote, seq, ack, flags, payload, payload_len, window, wscale, md5_key, md5_key_len, sack_blocks, sack_blocks_count, tfo_cookie, mark_ect, include_ts, ts_val, ts_ecr, no_sack_permitted);
                if (!packet.IsEmpty() && sink) {
                    sink(std::move(packet));
                }
            }
        }

        /* ---------------- TCP header parsing ---------------- */

        bool ParseTcp(const Byte* data, UInt32 len, TcpHdr& out) noexcept {
            if (NULLPTR == data || 20 > len) {
                return false;
            }
            const UInt16 off_field = static_cast<UInt16>(data[12] >> 4);
            const UInt32 hdr_len = static_cast<UInt32>(off_field) * 4;
            if (20 > hdr_len || hdr_len > len) {
                return false;
            }
            out.sport = Load16(data + 0);
            out.dport = Load16(data + 2);
            out.seq = Load32(data + 4);
            out.ack = Load32(data + 8);
            out.flags = static_cast<UInt16>(
                ((data[13] & 0x01) ? kFlagFin : 0) |
                ((data[13] & 0x02) ? kFlagSyn : 0) |
                ((data[13] & 0x04) ? kFlagRst : 0) |
                ((data[13] & 0x08) ? kFlagPsh : 0) |
                ((data[13] & 0x10) ? kFlagAck : 0) |
                ((data[13] & 0x20) ? kFlagUrg : 0) |
                ((data[13] & 0x40) ? kFlagEce : 0) |
                ((data[13] & 0x80) ? kFlagCwr : 0));
            out.window = Load16(data + 14);
            out.checksum = Load16(data + 16);
            out.urgent = Load16(data + 18);
            out.hdr_len = static_cast<Byte>(hdr_len);
            out.payload_off = static_cast<UInt16>(hdr_len);
            return true;
        }

        bool ParseTcpOpts(const Byte* data, UInt32 len, UInt32 hdr_len, TcpOpts& out) noexcept {
            if (NULLPTR == data || len < hdr_len || hdr_len < 20) {
                return false;
            }
            UInt32 off = 20;
            const UInt32 end = hdr_len;
            while (off < end) {
                const Byte kind = data[off];
                if (0 == kind) {
                    break;  // EOL
                }
                if (1 == kind) {
                    ++off;  // NOP
                    continue;
                }
                if ((off + 1) >= end) {
                    return false;  // truncated length byte
                }
                const Byte opt_len = data[off + 1];
                if (opt_len < 2 || (off + opt_len) > end) {
                    return false;  // malformed option length
                }
                switch (kind) {
                case 2:  // MSS (RFC 793)
                    if (4 == opt_len) {
                        out.has_mss = true;
                        out.mss = static_cast<UInt16>((static_cast<UInt16>(data[off + 2]) << 8) | data[off + 3]);
                    }
                    break;
                case 3:  // Window scale (RFC 7323)
                    if (3 == opt_len) {
                        out.has_wscale = true;
                        out.wscale = data[off + 2];
                        if (14 < out.wscale) {
                            out.wscale = 14;
                        }
                    }
                    break;
                case 4:  // SACK permitted (RFC 2018)
                    if (2 == opt_len) {
                        out.has_sack = true;
                    }
                    break;
                case 5: {  // SACK blocks (RFC 2018)
                    const UInt32 n = (opt_len - 2) / 8;
                    if (1 <= n && n <= 4 && (off + opt_len) <= end) {
                        out.has_sack = true;
                        out.sack_count = static_cast<Byte>(n);
                        for (UInt32 b = 0; b < n; ++b) {
                            out.sack[b][0] = Load32(data + off + 2 + b * 8);
                            out.sack[b][1] = Load32(data + off + 6 + b * 8);
                        }
                        // RFC 2018 �? the first SACK block is the most
                        // recently received block, so a compliant peer may
                        // send blocks most-recent-first. The sender-side
                        // recovery walk (RetransmitEarliestMissing) iterates
                        // blocks with a monotonic cursor and requires
                        // ascending seq order - normalize here so the walk is
                        // order-independent (also robust against Linux, which
                        // sends most-recent-first).
                        for (UInt32 a = 1; a < n; ++a) {
                            const UInt32 key_l = out.sack[a][0];
                            const UInt32 key_r = out.sack[a][1];
                            UInt32 j = a;
                            while (0 < j && SeqLt(key_l, out.sack[j - 1][0])) {
                                out.sack[j][0] = out.sack[j - 1][0];
                                out.sack[j][1] = out.sack[j - 1][1];
                                --j;
                            }
                            out.sack[j][0] = key_l;
                            out.sack[j][1] = key_r;
                        }
                    }
                    break;
                }
                case 8:  // Timestamps (RFC 7323)
                    if (10 == opt_len) {
                        out.has_timestamp = true;
                        out.ts_val = Load32(data + off + 2);
                        out.ts_ecr = Load32(data + off + 6);
                    }
                    break;
                case 34: {  // TCP Fast Open cookie (RFC 7413)
                    // RFC 7413: opt_len = 2 + cookie_len; cookies span 4-16
                    // bytes (opt_len 6-18). Linux servers send 16-byte cookies
                    // (opt_len 18); accept the full range and keep the leading
                    // kTfoCookieLen bytes (internal storage and the SYN builder
                    // are fixed-length 8 bytes).
                    if (2 + kTfoMinCookieLen <= opt_len && opt_len <= 2 + kTfoMaxCookieLen) {
                        out.has_tfo = true;
                        const UInt32 n = static_cast<UInt32>(opt_len - 2) < kTfoCookieLen
                                             ? static_cast<UInt32>(opt_len - 2)
                                             : kTfoCookieLen;
                        for (UInt32 i = 0; i < n; ++i) {
                            out.tfo_cookie[i] = data[off + 2 + i];
                        }
                    }
                    break;
                }
                default:
                    break;  // unknown option: skip by length
                }
                off += opt_len;
            }
            return true;
        }

        /* ---------------- TcpConn ---------------- */

        TimePoint TcpConn::NowUs() noexcept {
            return static_cast<TimePoint>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        }

        void TcpConn::MaybeMarkAppLimited(UInt32 inflight, TimePoint now) noexcept {
            // Kernel tcp_rate_check_app_limited (tcp_rate_v66.c:194-207):
            //   1. write_seq - snd_nxt < mss          -> pending_send_ < mss
            //   2. nothing queued in the host (qdisc/NIC) -> tx_idle: the
            //      sender has no pending bytes and no pacing-gated backlog
            //   3. tcp_packets_in_flight < snd_cwnd    -> packets, not bytes
            //   4. lost_out <= retrans_out             -> per-segment markers
            // (4) is deliberately looser than the old "cc_.lost == 0": bytes
            // already retransmitted are no longer outstanding losses.
            const UInt32 cwnd_pkts = cc_.snd_cwnd;
            const UInt32 inflight_pkts = (0 < peer_mss_)
                ? ((inflight + peer_mss_ - 1) / peer_mss_) : inflight;
            // tx_idle: no buffered bytes AND no pacing-gated backlog (the
            // pacing deadline stands in for the host qdisc's queued packets;
            // a connection waiting on the pacing clock is NOT idle).
            const bool tx_idle = pending_send_.empty() &&
                                 (0 == pacing_deadline_ || now >= pacing_deadline_);
            if (cc::IsAppLimited(static_cast<UInt32>(pending_send_.size()), tx_idle,
                                 inflight_pkts, cwnd_pkts,
                                 lost_out_pkts_, retrans_out_pkts_, peer_mss_)) {
                // Kernel tp->app_limited = tp->delivered + tcp_packets_in_flight
                // (PACKET domain, tcp_rate_v66.c:205-206); 0 is encoded as 1.
                const UInt64 marker = cc_.delivered_pkts + inflight_pkts;
                cc_.app_limited = (0 != marker) ? static_cast<UInt32>(marker) : 1u;
            }
        }

        void TcpConn::MarkPoolLimited(UInt32 inflight) noexcept {
            // Brief pressure with an active ACK clock still yields useful
            // path samples. Only a drained pipe or an aged waiter is limited.
            if (0 != inflight && !tx_waiter_.IsWaiting()) return;
            // Waiting for local TX memory does not measure path bandwidth.
            // Existing segments keep their send-time sampling flags; newly
            // emitted segments carry the local-resource limitation marker.
            const UInt32 packets = peer_mss_ > 0
                ? (inflight + peer_mss_ - 1) / peer_mss_ : inflight;
            const UInt32 marker = static_cast<UInt32>(cc_.delivered_pkts + packets);
            cc_.app_limited = (0 != marker) ? marker : 1u;
        }

        void TcpConn::ClearAppLimitedMarker() noexcept {
            // Kernel tcp_rate_gen (tcp_rate_66.c:123-125):
            //   if (tp->app_limited && after(tp->delivered, tp->app_limited))
            //       tp->app_limited = 0;
            // after() is the 32-bit wrapping comparison, hence the Int32 cast
            // of the UInt32 difference. Both the marker and the comparison
            // are in the PACKET domain (tp->delivered counts skb pcount).
            if (0 != cc_.app_limited &&
                static_cast<Int32>(static_cast<UInt32>(cc_.delivered_pkts) - cc_.app_limited) > 0) {
                cc_.app_limited = 0;
            }
        }

        UInt32 TcpConn::PacingEdtUs(TimePoint now) const noexcept {
            // Kernel interval_to_edt (tcp_kcc.c:5019-5022):
            //   edt_ns = max(tp->tcp_wstamp_ns, now_ns)
            //   interval_us = (edt_ns - now_ns) / NSEC_PER_USEC
            // TcpConn::pacing_deadline_ is the tcp_wstamp_ns equivalent and
            // is already MICROSECONDS (NowUs() is duration_cast<microseconds>,
            // and pacing_deadline_ = now + len*1e6/pacing_rate). No unit
            // conversion, no rounding: the remaining microseconds are the
            // pacing-queue depth.
            return (pacing_deadline_ > now)
                ? static_cast<UInt32>(pacing_deadline_ - now)
                : 0;
        }

        void TcpConn::NotifyTxStart(bool pipe_empty) noexcept {
            if (!pipe_empty || NULLPTR == cc_ops_ || NULLPTR == cc_ops_->cwnd_event) {
                return;
            }
            const UInt64 old_rate = cc_.pacing_rate;
            cc_ops_->cwnd_event(&cc_, cc::kCaEventTxStart);
            if (cc_.pacing_rate != old_rate) {
                pacing_deadline_ = 0;
            }
        }

        TcpConn::TcpConn(TcpState state, const Endpoint& local, const Endpoint& remote, UInt32 iss, UInt32 irs, TxSink sink) noexcept
            : state_(state), local_(local), remote_(remote), iss_(iss), irs_(irs), sink_(std::move(sink)) {
            snd_una_ = iss_ + 1;  // SYN occupies one sequence number
            snd_nxt_ = iss_ + 1;
            rcv_nxt_ = irs_ + 1;  // peer SYN occupies one sequence number
            window_ = kDefaultWindow;
            rcv_wnd_ = kDefaultWindow;
            snd_wnd_ = kDefaultWindow;
            // Kernel tp->max_window starts at the SYN's advertised window
            // (tcp_input_66.c:6409) and only grows (tcp_input_66.c:3596-3597).
            max_window_ = kDefaultWindow;
            // RFC 6928 (Linux initcwnd): initial window = 10 segments at
            // MSS 1460; ssthresh starts unlimited (slow start first).
            cc_.snd_cwnd = 10;
            cc_.snd_ssthresh = 0x7FFFFFFF;
            cc_.mss = peer_mss_;
            cc_.rcv_wnd = rcv_wnd_;
            cc_.snd_wnd = snd_wnd_;
        }

        TcpConn::~TcpConn() noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->release) {
                cc_ops_->release(&cc_);
            }
        }

        bool TcpConn::SetCongestionControl(const char* name) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->release) {
                cc_ops_->release(&cc_);
                cc_ops_ = NULLPTR;
            }
            if (NULLPTR == name || 0 == name[0] || 0 == std::strcmp(name, "reno")) {
                return true;  // NULLPTR/empty/"reno" -> built-in Reno (RFC 5681)
            }
            cc::XtcpCongestionOps copy;
            if (!cc::GetCongestionControl(name, copy)) {
                return false;  // unknown or disabled
            }
            // Take a private copy instead of borrowing the registry entry:
            // a concurrent Unregister (name=NULLPTR) or re-Register (struct
            // overwrite) must never tear the hook table a live connection
            // is reading through cc_ops_ (TOCTOU race).
            cc_ops_owner_ = std::make_unique<cc::XtcpCongestionOps>(copy);
            cc_ops_ = cc_ops_owner_.get();
            if (NULLPTR != cc_ops_->init) {
                cc_ops_->init(&cc_);
            }
            return true;
        }

        void TcpConn::Transition(TcpState next) noexcept {
            state_ = next;
            // Closing states must keep being swept: the reclamation pass in
            // PollAckTimers reads state/deadline before the dirty fast path.
            if (TcpState::kClosed == next || TcpState::kTimeWait == next) {
                tx_waiter_.Cancel();
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
            // Bug(close): a closed connection must stop sending. Reaching
            // kClosed via RST / Abort / LastAck-ACK / RTO-exhaustion can leave
            // the RTO and delayed-ACK timers armed with in-flight data in the
            // retransmission queue; the next PollAckTimers round would then
            // re-send those segments and flush a stale ACK from a dead flow.
            if (TcpState::kClosed == next) {
                rto_deadline_ = 0;
                persist_deadline_ = 0;
                retrans_queue_.clear();
                // The O(1) pipe sums mirror the queue: drop them together.
                pipe_sacked_bytes_ = 0;
                pipe_lost_bytes_ = 0;
                pipe_retrans_bytes_ = 0;
                ack_pending_ = false;
                ack_count_ = 0;
                ack_deadline_ = 0;
                close_pending_ = false;
            }
        }

        void TcpConn::SendSegment(UInt32 seq, UInt32 ack, UInt16 flags, const Byte* payload, UInt32 payload_len) noexcept {
            // RFC 3168 s6.1.2: a pending CWR (we reduced cwnd on an ECE) is
            // emitted on the next DATA segment per the RFC - but when no data
            // flows, Linux also puts it on a pure ACK so the peer stops ECEing
            // promptly (tcp_ecn_send applies CWR to any outgoing segment).
            // One-shot: consumed by whichever segment goes out first. SYN/RST
            // never carry CWR.
            UInt16 out_flags = flags;
            if (cwr_pending_ && 0 == (flags & (kFlagSyn | kFlagRst))) {
                out_flags |= kFlagCwr;
                cwr_pending_ = false;
            }
            // Advertise the receive window scaled by our WSOPT factor.
            const UInt16 advertised = AdvertisedWindow();
            // RFC 2018: piggyback SACK blocks on ACKs while we hold out-of-order
            // data, so the sender can retransmit every gap (not just the front).
            // Only when the peer negotiated SACK (sent SACK-permitted on its
            // SYN/SYN+ACK): sending SACK blocks to a non-SACK peer is a protocol
            // violation (RFC 2018 2) even though Linux tolerates it.
            UInt32 sack_buf[8];
            Byte sack_n = 0;
            if (0 == (flags & (kFlagSyn | kFlagRst)) && sack_ok_) {
                // RFC 2883 D-SACK: the FIRST SACK block advertises the most
                // recent duplicate (data the peer already had). The sender
                // uses it to detect spurious retransmissions and undo its
                // recovery cut.
                if (dsack_pending_) {
                    sack_buf[0] = dsack_left_;
                    sack_buf[1] = dsack_right_;
                    dsack_pending_ = false;
                    sack_n = 1;
                }
                if (!ooo_.empty()) {
                    const Byte n2 = BuildSackRanges(sack_buf + 2 * sack_n,
                                                    static_cast<Byte>(4 - sack_n));
                    sack_n = static_cast<Byte>(sack_n + n2);
                }
            }
            // RFC 7323: the segments built HERE (ACKs and their piggyback
            // data) carry the TSopt (tsval = our clock, tsecr = the peer's
            // last tsval). NOTE: the direct data paths (SendData/
            // FlushPendingSend/retransmit rebuilds) deliberately omit the
            // TSopt - the RTO retransmit is the one exception (fresh_ts,
            // RFC 3522 Eifel needs it).
            const bool include_ts = timestamps_ok_ && 0 == (flags & (kFlagSyn | kFlagRst));
            const UInt32 ts_val = include_ts ? static_cast<UInt32>((NowUs() / 1000) & 0xFFFFFFFF) : 0;
            const UInt32 ts_ecr = include_ts ? ts_recent_ : 0;
            // RFC 2018: SACK-permitted is a two-way offer - a SYN+ACK answers
            // the peer's SYN only if the peer offered it (peer_syn_sack_).
            // kTcpNoSackPermitted suppresses OUR offer on the SYN; the
            // SYN+ACK then also stays SACK-less (the peer cannot enable SACK
            // unilaterally - parity with the kernel's tcp_sack=0).
            const bool sack_offer = (0 != (flags & kFlagSyn)) &&
                (no_sack_permitted_ || (0 != (flags & kFlagAck) && !peer_syn_sack_));
            SendSegmentPacket(local_, remote_, seq, ack, out_flags, payload, payload_len, advertised, sink_, rcv_wscale_,
                              Md5Key(), Md5KeyLen(), (0 < sack_n) ? sack_buf : NULLPTR, sack_n, NULLPTR, false,
                              include_ts, ts_val, ts_ecr, sack_offer);
        }

        Byte TcpConn::BuildSackRanges(UInt32* out, Byte max_pairs) const noexcept {
            // Merge the out-of-order buffer into contiguous ranges:
            // [seq, seq + len).
            // ooo_ is keyed by raw sequence; walk it in RFC 1982 order (SeqLt)
            // instead of raw std::map order so ranges on opposite sides of a
            // 2^32 wrap merge correctly. When rcv_nxt_ nears the wrap point, a
            // raw-ascending pass places a post-wrap range (e.g. seq 0x0)
            // before a pre-wrap range (e.g. 0xFFFFFFF0) and the SeqLe merge
            // folds the pre-wrap range away (or across a real gap) - the SACK
            // under-advertises and the peer redundantly retransmits.
            Byte n = 0;
            UInt32 cur_left = 0, cur_right = 0;
            bool have = false;
            // Fast path: when the window does not straddle the 2^32 wrap,
            // the post-filter keys all lie numerically at/after rcv_nxt_, so
            // the raw map order (ascending key) IS the RFC 1982 order and no
            // sort is needed. A small stack buffer then absorbs the common
            // few-segment case with zero heap traffic.
            bool wrap = false;
            std::pair<UInt32, UInt32> stack_buf[16];
            std::vector<std::pair<UInt32, UInt32>> heap_buf;
            UInt32 seg_count = 0;
            for (const auto& kv : ooo_) {
                if (SeqLt(kv.first, rcv_nxt_)) {
                    // Stale entry: already covered by the cumulative ACK
                    // frontier - never advertise it as newly SACKed data.
                    continue;
                }
                if (kv.first < rcv_nxt_) {
                    wrap = true;  // a post-wrap key below the frontier numerically
                }
                if (seg_count < 16) {
                    stack_buf[seg_count++] = { kv.first, static_cast<UInt32>(kv.second.data.size()) };
                } else {
                    if (heap_buf.empty()) {
                        heap_buf.reserve(ooo_.size());
                    }
                    heap_buf.emplace_back(kv.first, static_cast<UInt32>(kv.second.data.size()));
                }
            }
            if (wrap) {
                // Wrapped window: the map's ascending-key order is NOT the
                // sequence order. Fold the stack entries into the heap and
                // restore the RFC 1982 ordering on the single combined set.
                const UInt32 sn = seg_count < 16 ? seg_count : 16;
                if (heap_buf.empty()) {
                    heap_buf.reserve(ooo_.size());
                }
                for (UInt32 i = 0; i < sn; ++i) {
                    heap_buf.push_back(stack_buf[i]);
                }
                seg_count = 0;
                const auto cmp = [](const std::pair<UInt32, UInt32>& a, const std::pair<UInt32, UInt32>& b) {
                    return SeqLt(a.first, b.first);
                };
                std::sort(heap_buf.begin(), heap_buf.end(), cmp);
            }
            const UInt32 stack_n = seg_count < 16 ? seg_count : 16;
            for (UInt32 i = 0; i < stack_n; ++i) {
                const UInt32 left = stack_buf[i].first;
                const UInt32 right = left + stack_buf[i].second;
                if (!have) {
                    cur_left = left;
                    cur_right = right;
                    have = true;
                    continue;
                }
                if (SeqLe(left, cur_right)) {  // contiguous or overlapping
                    if (SeqLt(cur_right, right)) {
                        cur_right = right;
                    }
                    continue;
                }
                if (n < max_pairs) {
                    out[n * 2] = cur_left;
                    out[n * 2 + 1] = cur_right;
                    ++n;
                }
                cur_left = left;
                cur_right = right;
            }
            for (const auto& pr : heap_buf) {
                const UInt32 left = pr.first;
                const UInt32 right = left + pr.second;
                if (!have) {
                    cur_left = left;
                    cur_right = right;
                    have = true;
                    continue;
                }
                if (SeqLe(left, cur_right)) {  // contiguous or overlapping
                    if (SeqLt(cur_right, right)) {
                        cur_right = right;
                    }
                    continue;
                }
                if (n < max_pairs) {
                    out[n * 2] = cur_left;
                    out[n * 2 + 1] = cur_right;
                    ++n;
                }
                cur_left = left;
                cur_right = right;
            }
            if (have && n < max_pairs) {
                out[n * 2] = cur_left;
                out[n * 2 + 1] = cur_right;
                ++n;
            }
            // RFC 2018 �? the first SACK block must be the most recently
            // received block. ooo_ is keyed by seq (no insertion order), so
            // approximate "most recent" with the largest-seq block - the last
            // emitted (blocks above are ascending). Swap it into slot 0.
            // The peer normalizes to ascending on parse (ParseTcpOpts), so
            // this reordering never affects the sender-side recovery walk.
            if (1 < n) {
                const UInt32 first_l = out[0];
                const UInt32 first_r = out[1];
                out[0] = out[(n - 1) * 2];
                out[1] = out[(n - 1) * 2 + 1];
                out[(n - 1) * 2] = first_l;
                out[(n - 1) * 2 + 1] = first_r;
            }
            return n;
        }

        void TcpConn::UpdateRto(UInt32 sample_us) noexcept {
            if (0 == srtt_) {
                // RFC 6298: first sample initializes srtt and rttvar.
                srtt_ = sample_us;
                rttvar_ = sample_us / 2;
                rto_ = static_cast<UInt32>(static_cast<UInt64>(srtt_) + 4ull * rttvar_);
            } else {
                // 64-bit math: 7*srtt_ / 4*rttvar_ overflow UInt32 once the
                // RTT reaches ~10 minutes (a pathological but reachable value
                // after a long outage's late ACK).
                rttvar_ = static_cast<UInt32>((3ull * rttvar_ + static_cast<UInt64>(std::llabs(static_cast<Int64>(srtt_) - static_cast<Int64>(sample_us)))) / 4);
                srtt_ = static_cast<UInt32>((7ull * srtt_ + sample_us) / 8);
                rto_ = static_cast<UInt32>(static_cast<UInt64>(srtt_) + 4ull * rttvar_);
            }
            if (rto_ > kMaxRto) {
                rto_ = kMaxRto;
            }
            // Linux TCP_RTO_MIN (200ms) parity: a sub-200ms floor (e.g. the
            // 1ms tcp_rto_min_us tuning value) would let the retransmission
            // timer fire mid-recovery on sub-millisecond-RTT paths (e.g.
            // back-to-back or low-latency LAN), aborting a healthy SACK
            // recovery with a spurious window cut. Note RFC 6298 s2.4 asks
            // for RTO >= 1s (SHOULD); 200ms is the Linux convention, not an
            // RFC allowance.
            if (rto_ < 200000) {
                rto_ = 200000;  // 200ms floor (Linux TCP_RTO_MIN)
            }
        }

        void TcpConn::ArmRetransmit(TimePoint now, UInt32 interval_us) noexcept {
            // interval_us == 0 means "use the base RTO" - the data-path call
            // sites (now + rto_) are unchanged; handshake/close sites pass a
            // doubled local backoff variable instead of the fixed rto_.
            rto_deadline_ = now + ((0 == interval_us) ? rto_ : interval_us);
            timers_dirty_.store(true, std::memory_order_relaxed);
        }

        /**
         * @brief Emits one cumulative rate sample (kernel tcp_rate_gen).
         *
         * Kernel tcp_ack calls tcp_rate_gen on EVERY ACK, including a
         * duplicate ACK whose only progress is SACK/DSACK delivery
         * (tcp_input.c:3879-3881 -> tcp_rate_gen at :3939). The port used to
         * emit only on cumulative-ACK advance, so a DSACK-only dup-ACK
         * produced no sample at all and KCC never saw the delivered packet.
         * Both call sites (cumulative ACK and SACK/DSACK dup-ACK) share this
         * one implementation so the sampling window rules cannot drift.
         */
        void TcpConn::EmitRateSample(TimePoint now, UInt32 acked, UInt32 rtt_sample,
                                    UInt64 prior_in_flight_bytes, UInt32 ack) noexcept {
            // Kernel tcp_rate_gen (tcp_rate_66.c:123-125) runs on EVERY ACK,
            // cumulative or duplicate, and its FIRST statement clears the
            // app-limited marker:
            //   if (tp->app_limited && after(tp->delivered, tp->app_limited))
            //       tp->app_limited = 0;
            // The port used to clear it only inside the cumulative-ACK branch,
            // so a SACK/DSACK-only dup-ACK left a stale marker latched and the
            // next emitted segment carried is_app_limited=1 (tcp_rate_66.c:69)
            // although the bubble had been ACKed and gone (A2/A3).
            ClearAppLimitedMarker();
            if (0 == last_rate_sample_) {
                // First cumulative ACK: establish the sample base (this
                // ACK's bytes fold into the next sample's window). A
                // degenerate (interval 0) sample is still delivered so
                // ACK-driven CC hooks (e.g. a pacing-rate raise) fire
                // on the first ACK.
                last_rate_sample_ = now;
                last_delivered_ = cc_.delivered;
                last_delivered_pkts_ = cc_.delivered_pkts;
                cc::RateSample rs;
                rs.acked = acked;
                rs.delivered = 0;
                rs.rtt_us = rtt_sample;
                rs.lost = 0;
                rs.interval_us = 0;
                rs.is_app_limited = batch_app_limited_;
                // Degenerate sample: no valid window information. Its
                // bytes fold into the next sample, so the batch
                // accumulators must NOT be reset here.
                rs.prior_delivered = 0;
                rs.delivered_total = cc_.delivered;
                rs.is_ack_delayed = false;
                rs.delivered_pkts = 0;
                rs.prior_delivered_pkts = 0;
                rs.delivered_total_pkts = cc_.delivered_pkts;
                rs.prior_in_flight_bytes = prior_in_flight_bytes;
                rs.pacing_edt_us = PacingEdtUs(now);
                // Kernel CC hooks read tcp_packets_in_flight(tp) LIVE. The
                // cached cc_.inflight is only refreshed on transmit, so a SACK
                // that retired segments would leave it inflated for KCC's
                // packet_conservation / DRAIN gates (audit B5-D3 / B6-D1).
                cc_.inflight = PipeInFlightBytes();
                cc::ApplyRateSample(&cc_, cc_ops_, &rs, ack);
            } else {
                const UInt32 interval_us = static_cast<UInt32>(
                    (now > last_rate_sample_) ? (now - last_rate_sample_) : 0);
                if (0 < interval_us) {
                    // Time advanced since the last sample: emit the
                    // delivered delta accumulated over that window
                    // (with the one-shot loss report), then restart
                    // the window.
                    const UInt64 delivered_delta = cc_.delivered - last_delivered_;
                    const UInt64 delivered_pkts_delta =
                        cc_.delivered_pkts - last_delivered_pkts_;
                    const UInt32 lost_report = (cc_.lost > 0xFFFFFFFFull)
                        ? 0xFFFFFFFFu
                        : static_cast<UInt32>(cc_.lost);
                    const UInt32 lost_pkts_report = cc_.lost_pkts;
                    cc_.lost = 0;
                    cc_.lost_pkts = 0;
                    cc::RateSample rs;
                    rs.acked = acked;
                    rs.delivered = (delivered_delta > 0xFFFFFFFFull)
                        ? 0xFFFFFFFFu
                        : static_cast<UInt32>(delivered_delta);
                    rs.rtt_us = rtt_sample;
                    rs.lost = lost_report;
                    rs.lost_pkts = lost_pkts_report;
                    // Bandwidth = delivered / interval (KCC/BBR need
                    // the real elapsed time between rate samples).
                    rs.interval_us = interval_us;
                    rs.is_app_limited = batch_app_limited_;
                    rs.prior_delivered = batch_prior_delivered_;
                    rs.delivered_total = cc_.delivered;
                    rs.is_ack_delayed = last_ack_delayed_;
                    // Packet domain (KCC): the delta and the send-time
                    // snapshot both count tcp_skb_pcount.
                    rs.delivered_pkts = (delivered_pkts_delta > 0xFFFFFFFFull)
                        ? 0xFFFFFFFFu
                        : static_cast<UInt32>(delivered_pkts_delta);
                    rs.prior_delivered_pkts = batch_prior_delivered_pkts_;
                    rs.delivered_total_pkts = cc_.delivered_pkts;
                    rs.prior_in_flight_bytes = prior_in_flight_bytes;
                    rs.pacing_edt_us = PacingEdtUs(now);
                    // See the note in the degenerate-sample branch: the CC
                    // hooks consume the live pipe, not a stale scalar.
                    cc_.inflight = PipeInFlightBytes();
                    last_rate_sample_ = now;
                    last_delivered_ = cc_.delivered;
                    last_delivered_pkts_ = cc_.delivered_pkts;
                    cc::ApplyRateSample(&cc_, cc_ops_, &rs, ack);
                    // The emitted sample closes this window; the next
                    // one starts a fresh batch.
                    batch_prior_delivered_ = 0;
                    batch_prior_delivered_pkts_ = 0;
                    batch_app_limited_ = 0;
                    batch_retrans_ = false;
                    last_ack_delayed_ = false;
                }
                // Same-tick ACK burst (interval == 0): the window stays
                // open; no sample is emitted so the next real one
                // reports the whole batch.
            }
        }

        void TcpConn::RetransmitFront(TimePoint now, bool fresh_ts) noexcept {
            if (retrans_queue_.empty()) {
                rto_deadline_ = 0;
                return;
            }
            SentSeg& seg = retrans_queue_.front();
            // Linux tcp_retries2 equivalent: a dead peer must eventually be
            // given up on - without a cap the RTO backoff retransmits forever
            // at the 60 s ceiling.
            if (kMaxDataRetries <= seg.retries) {
                Transition(TcpState::kClosed);
                NotifyStateChanged();  // timer-driven: the app must see the close
                timers_dirty_.store(true, std::memory_order_relaxed);
                rto_deadline_ = 0;
                return;
            }
            // RFC 1122 �?2.2.17: a retransmission must fit the peer's
            // advertised window. A zero window takes no data - the persist
            // probe owns that state, so skip the transmit (re-arm below) and
            // wait for a window-opening ACK instead of emitting an out-of-
            // window segment the peer drops. No bytes leave the wire, so the
            // retry budget must NOT be consumed (the increments live in the
            // successful-send block below, mirroring RetransmitEarliestMissing).
            if (0 == snd_wnd_) {
                // BUG-A: in a closing state (FinWait1/LastAck/Closing) a zero
                // window is a deadlock, not a probe state: persist probes are
                // gated to Established/CloseWait, FinWait1 has no closing
                // deadline, and keepalive is Established-only, so nothing would
                // ever reclaim this connection. Count the skipped transmit as a
                // failed send attempt so the kMaxDataRetries check above
                // eventually gives up and Transition(kClosed) releases the slot.
                // Established zero-window probing stays budget-free (persist
                // owns that state, and the window-ACK path clears the queue).
                if (TcpState::kFinWait1 == state_ || TcpState::kLastAck == state_ ||
                    TcpState::kClosing == state_) {
                    // A skipped transmit: consume the retry budget but do NOT
                    // set is_retrans (no bytes left the wire), so the pipe
                    // contribution is unchanged.
                    ++seg.retries;
                }
                rto_deadline_ = now + ((0 == seg.rto) ? rto_ : seg.rto);
                timers_dirty_.store(true, std::memory_order_relaxed);
                return;
            }
            const UInt32 tx_len = (seg.len < snd_wnd_) ? seg.len : snd_wnd_;
            buf::BufRef copy;
            if (seg.len == tx_len) {
                if (fresh_ts && timestamps_ok_ && !Md5Enabled()) {
                    // RFC 7323 s5.3 + RFC 3522 Eifel: the RTO retransmission
                    // must carry a FRESH TSval (rto_ts_val_, captured at the
                    // RTO entry) - the Eifel check at OnAckReceived compares
                    // the peer's echoed tsecr against rto_ts_val_ to
                    // distinguish a REAL loss (echo of the retransmission's
                    // tsval -> no undo) from a spurious RTO (echo of the
                    // original's tsval -> undo). Cloning the stored packet
                    // would resend the ORIGINAL TSval-less bytes and make the
                    // comparison meaningless (every RTO would look spurious).
                    // MD5 connections never carry the TSopt (option-space
                    // conflict, BuildSegmentPacket) - the Eifel undo is
                    // disabled for them by the timestamps_ok_ gate.
                    const buf::BufRef& orig = seg.data;
                    if (!orig.IsEmpty()) {
                        const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                        const UInt32 tcp_hdr_len =
                            static_cast<UInt32>(orig.Data()[ip_hdr_len + 12] >> 4) * 4;
                        // Keep the original segment's PSH/URG bits: the
                        // rebuild must carry the same flags as the stored
                        // packet (RFC 1011 PUSH semantics; a PSH-less
                        // retransmit would silently turn a pushed tail into
                        // an unpushed one). ACK is always set on data.
                        const Byte orig_flags = orig.Data()[ip_hdr_len + 13];
                        const UInt16 retx_flags =
                            static_cast<UInt16>(kFlagAck | (orig_flags & (kFlagPsh | kFlagUrg)));
                        copy = BuildSegmentPacket(local_, remote_, seg.seq, rcv_nxt_,
                                                  retx_flags,
                                                  orig.Data() + ip_hdr_len + tcp_hdr_len, tx_len,
                                                  AdvertisedWindow(), rcv_wscale_,
                                                  Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR,
                                                  ecn_active_, true, rto_ts_val_, ts_recent_);
                    }
                }
                if (copy.IsEmpty()) {
                    copy = seg.data.Clone();
                }
            } else {
                // Window trickle: the peer's window is smaller than the queued
                // segment - rebuild it truncated to the window (a SetLen
                // truncation would leave the IP/TCP length fields and
                // checksums stale).
                // seg.data stays alive in retrans_queue_ throughout the rebuild,
                // so read it in place (no Clone) - only the full-transmit path
                // above needs a copy because the sink adopts it.
                const buf::BufRef& orig = seg.data;
                if (!orig.IsEmpty()) {
                    const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                    const UInt32 tcp_hdr_len = static_cast<UInt32>(orig.Data()[ip_hdr_len + 12] >> 4) * 4;
                    copy = BuildSegmentPacket(local_, remote_, seg.seq, rcv_nxt_,
                                              kFlagAck,
                                              orig.Data() + ip_hdr_len + tcp_hdr_len, tx_len,
                                              AdvertisedWindow(), rcv_wscale_,
                                              Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                }
            }
            if (!copy.IsEmpty() && sink_) {
                // Kernel tcp_event_data_sent runs INSIDE __tcp_transmit_skb,
                // i.e. BEFORE tcp_retransmit_skb adds retrans_out
                // (tcp_output_v66.c:3383). The TX_START gate must therefore
                // read the pipe as it stood BEFORE this retransmission is
                // accounted: a fully-lost flight (lost_out already marked by
                // the RTO) reads 0 and the retransmit restarts the CC state.
                // Evaluated first, before any `seg` mutation below (the
                // retries increment alone would make the segment count as
                // retransmitted here).
                const bool pipe_empty = (0 == PipeInFlightBytes());
                // D20 reentrancy guard: complete every `seg`
                // update BEFORE the sink_ call. sink_ (EmitLocked) can re-enter
                // this connection (Tx -> peer -> OnSegment -> OnAckReceived ->
                // RetransmitFront, recursive syncobj_): the nested call may
                // pop_front retrans_queue_, invalidating this `seg` reference.
                // The retry budget and RTO backoff advance ONLY when bytes
                // actually leave the wire (mirror of RetransmitEarliestMissing,
                // tcp_fsm.cpp:1940-1941: the counters move after a successful emit).
                // A window-trickle rebuild that fails to allocate (pool
                // exhaustion -> empty copy) must NOT consume kMaxDataRetries:
                // the connection and the network are healthy, the peer's
                // window merely shrank below the queued segment length.
                const Byte old_is_retrans = seg.is_retrans;
                ++seg.retries;
                ++retransmit_count_;
                // Kernel tcp_rate_skb_sent refreshes tx.delivered on every
                // (re)transmission; TCPCB_RETRANS marks the skb so the ACK
                // heuristic can exclude it from the delayed-ACK test.
                seg.sent_delivered = cc_.delivered;
                seg.sent_delivered_pkts = cc_.delivered_pkts;
                seg.pkt_count = PktCount(seg.len, peer_mss_);
                // Kernel tcp_retransmit_skb (tcp_output_66.c:3325):
                //   tp->total_retrans += segs;
                // segs = tcp_skb_pcount(skb), i.e. the PACKET domain. The
                // DSACK credibility gate compares dsack_dups against it.
                total_retrans_pkts_ += seg.pkt_count;
                seg.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                seg.is_retrans = 1;
                // TCPCB_SACKED_RETRANS is now set: the segment counts in
                // retrans_out, so refresh its pipe contribution (0 -> 1).
                PipeReaccountSeg(seg, seg.sacked, seg.lost, old_is_retrans);
                seg.rto = (0 == seg.rto) ? rto_ : seg.rto;
                if (seg.rto < kMaxRto) {
                    seg.rto *= 2;  // exponential backoff
                    if (seg.rto > kMaxRto) {
                        seg.rto = kMaxRto;  // hard ceiling (the pre-check alone
                                            // lets a 40s rto double to 80s)
                    }
                }
                // Loss signal: the segment's bytes are lost on the wire. Mark
                // them only on the FIRST retransmit (kernel semantics: rate
                // sample "lost" = bytes newly marked lost since the last ACK,
                // not bytes re-sent). Repeated RTO retransmits of the same
                // segment must not re-deduct cwnd. Reported once to the CC
                // hook on the next rate sample (the accumulator is consumed
                // and reset there).
                if (1 == seg.retries) {
                    cc_.lost += seg.len;
                    // Packet-domain twin (kernel tp->lost): KCC subtracts
                    // rs->losses from cwnd directly, so the count must be
                    // segments, not a byte total rounded up later.
                    cc_.lost_pkts += seg.pkt_count;
                }
                // Karn (RFC 6298): a retransmitted segment must NOT contribute
                // an RTT sample - its ACK cannot distinguish the first send
                // from the retransmission, so sampling the original sent_at
                // would inflate srtt/min_rtt (hence BDP). Clear sent_at so the
                // RTT sampler (which skips sent_at == 0) never uses it.
                seg.sent_at = 0;
                // Kernel tcp_event_data_sent runs INSIDE __tcp_transmit_skb,
                // i.e. BEFORE tcp_retransmit_skb adds retrans_out
                // (tcp_output_v66.c:3383): the gate uses the pipe snapshot
                // taken above, so a fully-lost flight reads 0 and the
                // retransmit restarts the congestion state.
                NotifyTxStart(pipe_empty);
                // Kernel TCPCB_SACKED_RETRANS: retrans_out counts packets
                // actually retransmitted and still in flight. lost_out is NOT
                // touched here: a retransmission is not a loss verdict (the
                // loss decision marks it).
                retrans_out_pkts_ += seg.pkt_count;
                // Kernel tcp_output_66.c:3461-3462 (tcp_xmit_retransmit_queue,
                // i.e. every RETRANSMISSION actually put on the wire):
                //     if (tcp_in_cwnd_reduction(sk))
                //         tp->prr_out += tcp_skb_pcount(skb);
                // This is the second of the kernel's two prr_out increments
                // (the first is tcp_write_xmit, tcp_output_66.c:2787-2789,
                // mirrored by SendData/FlushPendingSend). Without it a
                // retransmission-driven recovery never spends PRR credit, so
                // `cwnd = ssthresh + delivered - out` climbs with every ACK and
                // PRR stops pacing the recovery (audit review batch 4, D).
                if (fast_recovery_) {
                    prr_out_ += seg.pkt_count;
                }
                // Kernel tcp_output_66.c:3390-3392 (every retransmission that
                // actually leaves the wire):
                //   if (tp->undo_retrans < 0) tp->undo_retrans = 0;
                //   tp->undo_retrans += tcp_skb_pcount(skb);
                // The entry assignment (CutCwnd, kernel tcp_init_undo
                // tcp_input.c:2106-2111) runs BEFORE this retransmit, so a
                // no-SACK dup-ACK entry starts at -1 and only this increment
                // makes the counter positive - which is what makes
                // tcp_may_undo (tcp_input.c:2530-2533) refuse the undo without
                // TSopt evidence. Without it a REAL loss is undone (a4rev54).
                if (undo_retrans_ < 0) {
                    undo_retrans_ = 0;
                }
                undo_retrans_ += static_cast<Int32>(seg.pkt_count);
                // D20: compute the re-arm deadline BEFORE the emit. sink_ can
                // re-enter this connection (Tx -> peer -> OnSegment ->
                // OnAckReceived -> RetransmitFront, recursive syncobj_) and
                // the nested call may pop_front retrans_queue_, which frees the
                // `seg` reference. Reading seg.rto after the emit was a
                // heap-use-after-free (ASan: test_tx_backpressure,
                // tcp_fsm.cpp:1541).
                const UInt32 rearm_rto = (0 == seg.rto) ? rto_ : seg.rto;
                // Emit LAST: the nested reentry must observe a consistent
                // (already-updated) retransmit state.
                sink_(std::move(copy));
                // Re-arm: after a successful send use the (backed-off) seg.rto;
                // on a failed rebuild (pool exhaustion, empty copy) re-arm at
                // the current seg.rto so the next RTO round retries once the
                // pool frees - the budget is untouched.
                rto_deadline_ = now + rearm_rto;
                timers_dirty_.store(true, std::memory_order_relaxed);
            } else {
                // Nothing left the wire (rebuild failed): `seg` is still alive,
                // so the re-arm may read it directly.
                rto_deadline_ = now + ((0 == seg.rto) ? rto_ : seg.rto);
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
        }

        void TcpConn::ResplitRetransQueue(UInt16 new_mss) noexcept {
            // RFC 1191 path-MTU reduction: an in-flight segment larger than
            // the new MSS must be re-segmented, or every retransmit re-sends
            // the oversized frame (DF is set, tcp_fsm.cpp BuildSegmentPacket)
            // and the router drops it - burning the retry budget until the
            // connection dies at kMaxDataRetries. Re-chunk the queue here so
            // RetransmitFront always emits <= new_mss bytes.
            if (retrans_queue_.empty() || 0 == new_mss) {
                return;
            }
            std::deque<SentSeg> resplit;
            while (!retrans_queue_.empty()) {
                SentSeg seg = std::move(retrans_queue_.front());
                retrans_queue_.pop_front();
                // The pipe sums are rebuilt wholesale at the end of this
                // function, so no per-segment subtraction is needed here.
                if (seg.len <= new_mss) {
                    resplit.push_back(std::move(seg));
                    continue;
                }
                // Rebuild the payload split at the new MSS boundary. The
                // stored packet holds IP+TCP headers + payload; rebuild each
                // chunk as a fresh segment (retries budget is preserved so a
                // split cannot extend the connection lifetime beyond the
                // kMaxDataRetries cap).
                // seg (moved out of the queue) owns the packet here; rebuild
                // directly from seg.data instead of cloning it.
                const buf::BufRef& orig = seg.data;
                if (orig.IsEmpty()) {
                    resplit.push_back(std::move(seg));
                    continue;
                }
                const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                const UInt32 tcp_hdr_len = static_cast<UInt32>(orig.Data()[ip_hdr_len + 12] >> 4) * 4;
                const Byte* payload = orig.Data() + ip_hdr_len + tcp_hdr_len;
                const UInt32 tcp_off = ip_hdr_len + tcp_hdr_len;
                if (orig.Len() < tcp_off) {
                    resplit.push_back(std::move(seg));
                    continue;
                }
                const UInt32 cap = Md5Enabled() ? ((new_mss > 20) ? (new_mss - 20) : 0) : new_mss;
                if (0 == cap) {
                    resplit.push_back(std::move(seg));
                    continue;
                }
                const UInt32 avail = orig.Len() - tcp_off;
                // All-or-nothing per segment: build every chunk first, commit
                // only when all succeed. A mid-split allocation failure would
                // otherwise drop the tail bytes (silent data loss).
                std::deque<SentSeg> parts;
                UInt32 off = 0;
                for (;;) {
                    if (off >= seg.len) {
                        break;
                    }
                    if (off >= avail) {
                        parts.clear();
                        break;
                    }
                    UInt32 chunk = seg.len - off;
                    if (chunk > cap) {
                        chunk = cap;
                    }
                    if (chunk > avail - off) {
                        chunk = avail - off;
                    }
                    SentSeg ns;
                    ns.seq = seg.seq + off;
                    ns.len = chunk;
                    ns.sent_at = seg.sent_at;
                    ns.rto = seg.rto;
                    ns.retries = seg.retries;
                    // A split is not a new transmission: inherit the send
                    // snapshots (the next real retransmit refreshes them).
                    ns.sent_delivered = seg.sent_delivered;
                    ns.sent_delivered_pkts = seg.sent_delivered_pkts;
                    ns.pkt_count = PktCount(chunk, peer_mss_);
                    ns.lost = seg.lost;
                    ns.app_limited = seg.app_limited;
                    ns.is_retrans = seg.is_retrans;
                    // A split inherits the retired retrans_out accounting:
                    // the pop path must not decrement it again.
                    ns.retrans_out_retired = seg.retrans_out_retired;
                    ns.data = BuildSegmentPacket(local_, remote_, ns.seq, rcv_nxt_,
                                                 kFlagAck,
                                                 payload + off, chunk,
                                                 AdvertisedWindow(), rcv_wscale_,
                                                 Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                    if (ns.data.IsEmpty()) {
                        parts.clear();  // allocation failed: keep the original
                        break;
                    }
                    parts.push_back(std::move(ns));
                    off += chunk;
                }
                if (parts.empty() && off < seg.len) {
                    resplit.push_back(std::move(seg));  // split incomplete: keep original
                    continue;
                }
                for (SentSeg& ps : parts) {
                    resplit.push_back(std::move(ps));
                }
            }
            retrans_queue_ = std::move(resplit);
            // Rebuild the O(1) pipe sums from the re-split queue. This path
            // only runs on an MSS change (RFC 1191), never per packet, so a
            // single walk here is free - and it keeps the incremental counters
            // provably consistent with whatever the split produced.
            pipe_sacked_bytes_ = 0;
            pipe_lost_bytes_ = 0;
            pipe_retrans_bytes_ = 0;
            for (const SentSeg& rs : retrans_queue_) {
                PipeAccountSeg(rs, +1);
            }
        }

        void TcpConn::OnRetransmitTimer(TimePoint now) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            // Bug(close): a closed connection must never retransmit - the
            // reclamation pass has (or will) remove it from the flow map.
            if (TcpState::kClosed == state_) {
                return;
            }
            if (0 == rto_deadline_ || now < rto_deadline_) {
                return;
            }
            rto_deadline_ = 0;
            // B3: a zero-window peer is probed EXCLUSIVELY by persist (RFC
            // 1122). RTO-retransmitting the queue would burn the
            // kMaxDataRetries budget on a peer that is alive but has no
            // buffer, killing the connection; it also double-fires with the
            // persist probe in the same poll round. Skip while persist owns
            // the probe loop (rto_deadline_ disarmed above; the ACK path
            // re-arms it once the window opens).
            if (0 == snd_wnd_ && 0 != persist_deadline_) {
                return;
            }
            if (TcpState::kSynSent == state_) {
                // RFC 793: a lost SYN is retransmitted with exponential
                // backoff, bounded by TCP_SYNCNT (Linux tcp_syn_retries).
                if (syn_retries_ <= syn_retry_count_) {
                    Transition(TcpState::kClosed);  // handshake abandoned
                    NotifyStateChanged();  // timer-driven: the app must see the close
                    timers_dirty_.store(true, std::memory_order_relaxed);
                    return;
                }
                ++syn_retry_count_;
                // RFC 7413: a lost fast-open SYN is retransmitted WITH its
                // early data (and cookie, so the server accepts the data) -
                // not as a bare SYN (a cookie-less SYN+data is refused).
                // RFC 3168 6.1.1: SYN retransmissions KEEP the ECE+CWR offer -
                // the RFC permits re-sending ECN-setup SYNs (the MAY to clear
                // is a retry-throttling option, not a prohibition), and Linux
                // re-sends the original SYN skb with its ECN bits intact.
                if (!tfo_syn_data_.empty()) {
                    if (has_tfo_cookie_) {
                        SendSegmentPacket(local_, remote_, iss_, 0,
                                          kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                                          tfo_syn_data_.data(),
                                          static_cast<UInt32>(tfo_syn_data_.size()),
                                          static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_, kWindowScaleOffer,
                                          Md5Key(), Md5KeyLen(), NULLPTR, 0, tfo_cookie_);
                    } else {
                        // No cookie: the early data was buffered in
                        // pending_send_ (it flushes after the handshake), so
                        // the retransmitted SYN is bare - a cookie-less
                        // SYN+data would only be refused by the server.
                        SendSegmentPacket(local_, remote_, iss_, 0,
                                          kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                                          NULLPTR, 0,
                                          static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_,
                                          kWindowScaleOffer, Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR);
                    }
                } else {
                    SendSegmentPacket(local_, remote_, iss_, 0,
                                      kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                                      NULLPTR, 0,
                                      static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_,
                                      kWindowScaleOffer, Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR);
                }
                // RFC 1122 �?2.3.5: handshake retransmits back off
                // exponentially, mirroring RetransmitFront's seg.rto doubling
                // (tcp_fsm.cpp:1075-1082) - a fixed rto_ re-arm fires the whole
                // syn_retries_ budget at a constant 1 s (Linux ~127 s for 6
                // retries; this now matches with 1,2,4,8,... capped at 60 s).
                syn_rto_ = (0 == syn_rto_) ? rto_ : syn_rto_;
                if (syn_rto_ < kMaxRto) {
                    syn_rto_ *= 2;
                    if (syn_rto_ > kMaxRto) {
                        syn_rto_ = kMaxRto;
                    }
                }
                ArmRetransmit(now, syn_rto_);
                return;
            }
            if (TcpState::kSynRcvd == state_) {
                // RFC 793: a lost SYN+ACK is retransmitted with backoff,
                // bounded by the same retransmission budget.
                if (syn_retries_ <= syn_retry_count_) {
                    Transition(TcpState::kClosed);  // handshake abandoned
                    NotifyStateChanged();  // timer-driven: the app must see the close
                    timers_dirty_.store(true, std::memory_order_relaxed);
                    return;
                }
                ++syn_retry_count_;
                // RFC 7413: the SYN+ACK retransmit carries the TFO cookie
                // again so the client can still learn it. The cookie binds to
                // the (client, server) endpoint triple, so a cookie learned by
                // one IP cannot be replayed from another or on a different
                // listener port.
                Byte cookie[8];
                UInt32 bound[4];
                TfoBoundAddr(bound);
                tfo_.Generate(bound, cookie);
                SendSegmentPacket(local_, remote_, iss_, rcv_nxt_,
                                  kFlagSyn | kFlagAck | (ecn_requested_ ? kFlagEce : 0),
                                  NULLPTR, 0, AdvertisedWindow(), sink_, rcv_wscale_,
                                  Md5Key(), Md5KeyLen(), NULLPTR, 0, cookie, false,
                                  false, 0, 0, !sack_ok_);
                // RFC 1122 �?2.3.5: the SYN+ACK retransmit backs off
                // exponentially (mirror of RetransmitFront seg.rto doubling,
                // tcp_fsm.cpp:1075-1082), not a fixed rto_ re-arm.
                syn_rto_ = (0 == syn_rto_) ? rto_ : syn_rto_;
                if (syn_rto_ < kMaxRto) {
                    syn_rto_ *= 2;
                    if (syn_rto_ > kMaxRto) {
                        syn_rto_ = kMaxRto;
                    }
                }
                ArmRetransmit(now, syn_rto_);
                return;
            }
            if (TcpState::kFinWait1 == state_ || TcpState::kLastAck == state_ ||
                TcpState::kClosing == state_) {
                // RFC 793: the FIN (seq snd_nxt_-1) follows all data. When
                // unacked data remains, retransmit the data first -
                // retransmitting only the FIN strands snd_una_ and the peer
                // never ACKs the FIN, deadlocking the close.
                if (!retrans_queue_.empty()) {
                    // RetransmitFront re-arms the deadline with the segment's
                    // backed-off rto itself (tcp_fsm.cpp:1113-1114) - an extra
                    // ArmRetransmit(now) here would OVERWRITE that doubled
                    // deadline with the base rto_, collapsing the exponential
                    // backoff to a fixed cadence (a dead peer would burn the
                    // 15-retry budget 15x faster than RFC 1122 intends).
                    RetransmitFront(now);
                    return;
                }
                // Only the FIN is in flight. Bound its retransmits like the
                // data path (kMaxDataRetries in RetransmitFront): the FIN
                // reuses syn_retry_count_ as its retry budget - it is always
                // 0 here (reset at both handshake completions, incremented
                // only in SynSent/SynRcvd, unreachable from these states) -
                // so a dead peer cannot hold the slot with 60 s FIN re-sends
                // forever.
                if (kMaxDataRetries <= syn_retry_count_) {
                    Transition(TcpState::kClosed);
                    NotifyStateChanged();  // timer-driven: the app must see the close
                    timers_dirty_.store(true, std::memory_order_relaxed);
                    rto_deadline_ = 0;
                    return;
                }
                ++syn_retry_count_;
                SendSegment(snd_nxt_ - 1, rcv_nxt_, kFlagFin | kFlagAck, NULLPTR, 0);
                // RFC 1122 �?2.3.5: the FIN retransmit backs off exponentially
                // (mirror of RetransmitFront seg.rto doubling, tcp_fsm.cpp:1081-1087). With a fixed rto_ re-arm the close gave up after
                // 15 s (15 x 1 s); now it doubles 1,2,4,... capped at 60 s.
                fin_rto_ = (0 == fin_rto_) ? rto_ : fin_rto_;
                if (fin_rto_ < kMaxRto) {
                    fin_rto_ *= 2;
                    if (fin_rto_ > kMaxRto) {
                        fin_rto_ = kMaxRto;
                    }
                }
                ArmRetransmit(now, fin_rto_);
                return;
            }
            if (retrans_queue_.empty()) {
                return;
            }
            // RFC 5681 RTO recovery: slow start to one segment after the cut.
            undo_marker_ = false;  // an RTO is a confirmed loss: no fast-recovery undo
            // RFC 3522 Eifel: capture the pre-cut window and the
            // retransmission's TSval so a spurious RTO (the peer merely
            // reordered / delayed its ACK) can be undone when the ACK echoes
            // the ORIGINAL timestamp instead of the retransmission's.
            // First-save gate: an RTO firing DURING an active
            // fast recovery (or a pending Eifel window) must NOT overwrite the
            // recovery's pre-cut window - the undo paths (D-SACK/Eifel/recovery
            // exit) read prior_cwnd_ and would otherwise restore the ALREADY-
            // halved value (half-undo). The recovery's prior stays authoritative
            // until its own undo fires.
            if (!fast_recovery_ && !rto_pending_) {
                prior_cwnd_ = cc_.snd_cwnd;
                prior_ssthresh_ = cc_.snd_ssthresh;
            }
            // RFC 3522 adjudication bases (kernel tp->retrans_stamp,
            // tcp_input.c:2454-2457): the FIRST retransmission's TSval of this
            // episode is the reference. Successive RTOs must refresh the TSval
            // they PUT ON THE WIRE (RFC 7323 s5.3 needs a new TSval per
            // retransmission, so rto_ts_val_ is rewritten below) but must NOT
            // advance the reference - otherwise an ACK echoing the first
            // retransmission would look "older than the latest" and a real loss
            // would be declared spurious (audit D03).
            if (!rto_pending_) {
                retrans_stamp_ts_ = 0;   // new episode: no reference yet
            }
            rto_ts_val_ = static_cast<UInt32>(NowUs() / 1000);
            if (0 == retrans_stamp_ts_) {
                retrans_stamp_ts_ = rto_ts_val_;
            }
            rto_pending_ = true;
            // The sequence end of the segment this RTO is about to retransmit:
            // a cumulative ACK reaching it answers the "spurious?" question even
            // when the peer never negotiated TSopt, so rto_pending_ can never be
            // pinned forever (audit D04). RetransmitFront may truncate to the
            // peer window; using the full segment end is conservative (the
            // adjudication simply waits for the rest of the segment).
            rto_retx_end_ = retrans_queue_.empty()
                ? 0 : (retrans_queue_.front().seq + retrans_queue_.front().len);
            // Kernel tcp_timeout_mark_lost (tcp_input_66.c:2123-2151): the RTO
            // walks the WHOLE retransmit tree and marks every skb that is not
            // TCPCB_SACKED_ACKED lost, before the window cut:
            //
            //     skb = head;
            //     skb_rbtree_walk_from(skb) {
            //         if (is_reneg) ...
            //         else if (tcp_is_rack(sk) && skb != head &&
            //                  tcp_rack_skb_timeout(tp, skb, 0) > 0)
            //             continue;   // recently sent: not lost yet
            //         tcp_mark_skb_lost(sk, skb);
            //     }
            //
            // tcp_mark_skb_lost (:1121) then does lost_out += pcount for each.
            // Marking only the head leaves the tail inside packets_out, so the
            // following tcp_enter_loss collapse
            //   cwnd = tcp_packets_in_flight(tp) + 1
            // (:2174) counts segments the kernel has already declared lost -
            // the post-timeout window comes out far above 1 (audit D14).
            //
            // The RACK arm (`skb != head && tcp_rack_skb_timeout > 0`) keeps
            // recently sent segments out of the loss set. The port has no
            // per-skb RACK timer: RackDetectLoss (:2739) runs the time-based
            // verdict on the ACK path and the RTO is the coarse fallback, so
            // every un-SACKed segment is treated as lost - the conservative
            // direction the kernel takes when RACK is not enabled
            // (tcp_is_rack() false). Marking MORE segments lost lowers the
            // collapse window; it never inflates it.
            for (SentSeg& s : retrans_queue_) {
                if (s.sacked >= s.len) {
                    continue;   // already delivered by SACK
                }
                if (0 == s.lost) {
                    s.lost = 1;
                    lost_out_pkts_ += s.pkt_count;
                    // LOST takes the segment out of the pipe: re-account it.
                    PipeReaccountSeg(s, s.sacked, 0, s.is_retrans);
                }
            }
            // Kernel tcp_enter_loss guard (tcp_input_66.c:2165-2173): the
            // reduction (ssthresh/prior_ssthresh/prior_cwnd) is recomputed
            // only when
            //   state <= Disorder  ||  !after(high_seq, snd_una)  ||
            //   (state == Loss && !icsk_retransmits)
            // A second timeout inside the SAME window therefore keeps the
            // first cut instead of halving it again - and, crucially, keeps
            // the FIRST prior_ssthresh/prior_cwnd snapshot (a repeated cut
            // would overwrite the undo target with an already-halved value).
            // cwnd = packets_in_flight + 1 is applied unconditionally by
            // tcp_enter_loss, so the window still collapses.
            const bool reduce_this_loss =
                (0 == cc_.ca_state) ||
                !SeqLt(snd_una_, high_seq_) ||
                (4 == cc_.ca_state && 0 == icsk_retransmits_);
            if (reduce_this_loss) {
                CutCwnd();
            } else {
                // Same-window retransmission: only the window collapses.
                const UInt32 pipe_pkts =
                    (PipeInFlightBytes() + peer_mss_ - 1) / peer_mss_;
                cc_.snd_cwnd = (0 < pipe_pkts) ? pipe_pkts + 1 : 1;
                cc_.snd_cwnd_cnt = 0;
            }
            ++icsk_retransmits_;
            SetCaState(4);   // kernel tcp_enter_loss: tcp_set_ca_state(CA_Loss)
            // Kernel tcp_enter_loss: tp->high_seq = tp->snd_nxt (the recovery
            // -end test is snd_una >= high_seq).
            high_seq_ = snd_nxt_;
            // Kernel tcp_enter_loss ends with
            //   tcp_snd_cwnd_set(tp, tcp_packets_in_flight(tp) + 1)
            // which is exactly what the plugin branch of CutCwnd already
            // applied (after the ssthresh hook and CA_EVENT_LOSS). Collapsing
            // to 1 on top of that is the legacy Reno-only convention; keep it
            // only for the classic path so a hook-owning CC (KCC/BBR/CUBIC)
            // is not silently overwritten with a one-segment window.
            if (NULLPTR == cc_ops_ || NULLPTR == cc_ops_->ssthresh) {
                cc_.snd_cwnd = 1;
            }
            cc_.snd_cwnd_cnt = 0;
            fast_recovery_ = false;
            RetransmitFront(now, true);  // fresh TSval: the Eifel undo (RFC 3522) needs it
        }

        bool TcpConn::VerifyMd5Segment(const Byte* key, UInt32 key_len,
                                       const Endpoint& local, const Endpoint& remote,
                                       Byte* t, UInt32 tcp_len) noexcept {
            if (NULLPTR == key || 0 == key_len) {
                return true;
            }
            // Find the MD5 option (kind 19) inside the TCP header.
            const Byte data_offset = static_cast<Byte>(t[12] >> 4);
            const UInt32 hdr_len = data_offset * 4;
            if (hdr_len < 22 || hdr_len > tcp_len) {
                return false;
            }
            UInt32 md5_off = 0;
            bool found = false;
            UInt32 off = 20;
            while (off + 1 < hdr_len) {
                const Byte kind = t[off];
                if (0 == kind) {
                    break;
                }
                if (1 == kind) {
                    ++off;
                    continue;
                }
                const Byte opt_len = t[off + 1];
                if (opt_len < 2 || (off + opt_len) > hdr_len) {
                    return false;
                }
                if (19 == kind) {
                    if (18 != opt_len || (off + 18) > hdr_len) {
                        return false;
                    }
                    md5_off = off;
                    found = true;
                    break;
                }
                off += opt_len;
            }
            if (!found) {
                return false;  // peer expected a signed segment
            }
            // Compute over the segment with checksum and MD5 fields zeroed.
            std::uint8_t saved[18];
            for (UInt32 i = 0; i < 18; ++i) {
                saved[i] = t[md5_off + i];
            }
            for (UInt32 i = 0; i < 16; ++i) {
                t[md5_off + 2 + i] = 0;
            }
            const Byte saved_csum0 = t[16];
            const Byte saved_csum1 = t[17];
            t[16] = 0;
            t[17] = 0;
            const bool is_v6 = (6 == remote.family);
            Byte pseudo[40];
            UInt32 pseudo_len = 0;
            if (is_v6) {
                for (UInt32 i = 0; i < 4; ++i) {
                    // Inbound segment: src = remote, dst = local.
                    const UInt32 src = remote.addr[i];
                    const UInt32 dst = local.addr[i];
                    Byte* sp = pseudo + i * 4;
                    Byte* dp = pseudo + 16 + i * 4;
                    sp[0] = static_cast<Byte>(src >> 24);
                    sp[1] = static_cast<Byte>(src >> 16);
                    sp[2] = static_cast<Byte>(src >> 8);
                    sp[3] = static_cast<Byte>(src & 0xFF);
                    dp[0] = static_cast<Byte>(dst >> 24);
                    dp[1] = static_cast<Byte>(dst >> 16);
                    dp[2] = static_cast<Byte>(dst >> 8);
                    dp[3] = static_cast<Byte>(dst & 0xFF);
                }
                pseudo[32] = static_cast<Byte>(tcp_len >> 24);
                pseudo[33] = static_cast<Byte>(tcp_len >> 16);
                pseudo[34] = static_cast<Byte>(tcp_len >> 8);
                pseudo[35] = static_cast<Byte>(tcp_len & 0xFF);
                pseudo[36] = 0;
                pseudo[37] = 0;
                pseudo[38] = 0;
                pseudo[39] = kProtoTcp;
                pseudo_len = 40;
            } else {
                pseudo[0] = static_cast<Byte>(remote.addr[0] >> 24);
                pseudo[1] = static_cast<Byte>(remote.addr[0] >> 16);
                pseudo[2] = static_cast<Byte>(remote.addr[0] >> 8);
                pseudo[3] = static_cast<Byte>(remote.addr[0] & 0xFF);
                pseudo[4] = static_cast<Byte>(local.addr[0] >> 24);
                pseudo[5] = static_cast<Byte>(local.addr[0] >> 16);
                pseudo[6] = static_cast<Byte>(local.addr[0] >> 8);
                pseudo[7] = static_cast<Byte>(local.addr[0] & 0xFF);
                pseudo[8] = 0;
                pseudo[9] = kProtoTcp;
                pseudo[10] = static_cast<Byte>((tcp_len >> 8) & 0xFF);
                pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
                pseudo_len = 12;
            }
            Md5Ctx ctx;
            Md5Init(ctx);
            Md5Update(ctx, pseudo, pseudo_len);
            Md5Update(ctx, t, tcp_len);
            Md5Update(ctx, key, key_len);
            std::uint8_t digest[16];
            Md5Final(ctx, digest);
            t[16] = saved_csum0;
            t[17] = saved_csum1;
            for (UInt32 i = 0; i < 18; ++i) {
                t[md5_off + i] = saved[i];
            }
            // Constant-time comparison (RFC 2385): fold every byte's XOR
            // difference into one accumulator with no early exit, so the
            // comparison latency does not leak digest bytes (timing side
            // channel; mirrors tfo.cpp Check()). saved[i+2] == the 16-byte
            // MD5 digest in the received TCP-MD5 option.
            Byte diff = 0;
            for (UInt32 i = 0; i < 16; ++i) {
                diff |= static_cast<Byte>(saved[i + 2] ^ digest[i]);
            }
            return 0 == diff;
        }

        bool TcpConn::TrimOooToFrontier() noexcept {
            bool changed = false;
            const auto trim = [&](std::map<UInt32, OutSeg>::iterator current) noexcept {
                const UInt32 skipped = rcv_nxt_ - current->first;
                const UInt32 length = static_cast<UInt32>(current->second.data.size());
                changed = true;
                if (skipped > length || (skipped == length && !current->second.fin)) {
                    ooo_bytes_ -= length;
                    ooo_.erase(current);
                    return;
                }
                // Keep only fresh bytes, including a FIN exactly at RCV.NXT.
                // Re-key the existing node without allocating another node.
                auto node = ooo_.extract(current);
                auto& segment = node.mapped();
                segment.data.erase(segment.data.begin(), segment.data.begin() + skipped);
                ooo_bytes_ -= skipped;
                node.key() = rcv_nxt_;
                auto existing = ooo_.find(rcv_nxt_);
                if (existing == ooo_.end()) {
                    ooo_.insert(std::move(node));
                } else if (segment.data.size() > existing->second.data.size()) {
                    ooo_bytes_ -= static_cast<UInt32>(existing->second.data.size());
                    existing->second = std::move(segment);
                } else {
                    if (segment.data.size() == existing->second.data.size()) {
                        existing->second.fin |= segment.fin;
                    }
                    ooo_bytes_ -= static_cast<UInt32>(segment.data.size());
                }
            };
            // TCP-old keys occupy at most two numeric map ranges around
            // wraparound. Visit only those ranges, never scan future entries
            // on every drain. Each old node is removed/re-keyed once, giving
            // O(N log N) map work over a drain (plus prefix compaction bytes).
            for (;;) {
                const auto boundary = ooo_.lower_bound(rcv_nxt_);
                if (boundary == ooo_.begin()) break;
                const auto previous = std::prev(boundary);
                if (!SeqLt(previous->first, rcv_nxt_)) break;
                trim(previous);
            }
            while (!ooo_.empty()) {
                const auto last = std::prev(ooo_.end());
                if (!SeqLt(last->first, rcv_nxt_)) break;
                trim(last);
            }
            return changed;
        }

        bool TcpConn::ProcessClosingData(const Byte* payload, UInt32 payload_len, UInt32 seq,
                                         bool has_fin, TimePoint now, UInt32 ts_val) noexcept {
            // RFC 793 half-close: the peer may still send data after our FIN
            // (e.g. an echo server answering before closing). Process it like
            // Established (deliver, reassemble out-of-order) and ACK
            // immediately; the closing states do not batch delayed ACKs.
            // Returns true when this call consumed the peer's FIN - the
            // closing-state caller must then advance the state machine
            // (TIME-WAIT / CLOSING / CLOSE-WAIT), or a peer FIN drained
            // through the out-of-order buffer would be ACKed while the FSM
            // stays put, skipping 2MSL (RFC 793) and stranding the
            // connection until the FIN-WAIT-2 timeout.
            (void)now;
            if (0 == payload_len) {
                if (!has_fin) {
                    return false;
                }
                if (seq == rcv_nxt_) {
                    // In-order pure FIN: consume now (RFC 793: the FIN
                    // occupies the sequence number after its data).
                    ++rcv_nxt_;
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                    return true;
                }
                if (SeqLt(seq, rcv_nxt_)) {
                    // Duplicate/old FIN: re-ACK the frontier, do not consume.
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                    return false;
                }
                // Out-of-order pure FIN: buffer for reassembly (mirror of the
                // Established path) so the FIN is consumed when the gap fills
                // instead of being dropped and retransmitted - otherwise the
                // peer's RTO round-trip inflates the close latency and, in
                // FIN-WAIT-1 with a fully-ACKed FIN, the retransmitted FIN
                // arrives after the RTO was disarmed and nothing advances
                // the state machine (stranded connection, no timers).
                const UInt32 wnd_end = rcv_nxt_ + rcv_wnd_;
                if (SeqLt(seq, wnd_end) || seq == wnd_end) {
                    if (ooo_.find(seq) == ooo_.end()) {
                        OutSeg entry;
                        entry.fin = true;
                        ooo_[seq] = std::move(entry);
                    }
                }
                SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                return false;
            }
            if (seq == rcv_nxt_) {
                // Advance RCV.NXT before the app callback so a send the app
                // makes inside it (echo/reply) carries an ACK covering the
                // just-delivered bytes (RFC 793); roll back on backpressure.
                const UInt32 prev_in = rcv_nxt_;
                rcv_nxt_ += payload_len;
                if (recv_cb_ && !recv_cb_(payload, payload_len)) {
                    // Backpressure: the app could not accept the data. Roll
                    // back, do not ACK - the peer RTOs and retransmits, so
                    // nothing is silently lost. Advertise window 0 (RFC 1122
                    // s4.2.3.4) so the peer persists instead of burning RTOs
                    // on data it cannot push.
                    rcv_nxt_ = prev_in;
                    rcv_blocked_ = true;
                    return false;
                }
                if (rcv_blocked_) {
                    ArmWindowUpdateAck(now);  // window reopens (RFC 1122 s4.2.3.4)
                }
                rcv_blocked_ = false;  // accepted: the receive window is open
                while (!ooo_.empty()) {
                    TrimOooToFrontier();
                    auto it = ooo_.find(rcv_nxt_);
                    if (it == ooo_.end()) {
                        break;
                    }
                    const OutSeg& seg = it->second;
                    const bool fin = seg.fin;  // capture before erase (seg aliases the node)
                    if (0 == seg.data.size()) {
                        // Pure-FIN entry (buffered by the closing-data path):
                        // consume without a recv_cb_ - a 0-byte callback
                        // could be misread as backpressure and refunded.
                        ooo_.erase(it);
                        if (fin) {
                            ++rcv_nxt_;
                            SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                            return true;
                        }
                        continue;
                    }
                    const UInt32 prev_drain = rcv_nxt_;
                    rcv_nxt_ += static_cast<UInt32>(seg.data.size());  // advance before callback
                    // RFC 7323: the drained segment is now in-order - its
                    // TSval advances TsRecent (the PAWS anchor).
                    if (0 != seg.ts_val) {
                        ts_recent_ = seg.ts_val;
                            ts_recent_stamp_ = static_cast<UInt32>((now / 1000) & 0xFFFFFFFF);
                    }
                    if (recv_cb_ && !recv_cb_(seg.data.data(), static_cast<UInt32>(seg.data.size()))) {
                        // Backpressure: drop this buffered segment (refund its
                        // bytes) and stop draining; the peer retransmits.
                        rcv_nxt_ = prev_drain;  // rollback
                                rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                                ArmWindowUpdateAck(now);
                                ooo_bytes_ -= static_cast<UInt32>(seg.data.size());
                        ooo_.erase(it);
                        break;
                    }
                    if (TcpState::kClosed == state_) {
                        // The recv handler aborted reentrantly: stop draining.
                        return false;
                    }
                    ooo_bytes_ -= static_cast<UInt32>(seg.data.size());
                    ooo_.erase(it);
                    if (fin) {
                        // Out-of-order FIN (RFC 793): consumed once its data
                        // fills the gap - advance past it and re-ACK; the
                        // caller uses the return value to advance the state
                        // machine (TIME-WAIT / CLOSING / CLOSE-WAIT).
                        ++rcv_nxt_;
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                        return true;
                    }
                }
                SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
            } else if (SeqLt(seq, rcv_nxt_)) {
                // Fully or partially old data: re-ACK the frontier. A
                // partially overlapping segment (seq < rcv_nxt_ < seg_end)
                // must not be dropped whole - its fresh suffix
                // [rcv_nxt_, seg_end) starts exactly at the receive
                // frontier, so deliver it in place (the peer may have resent
                // a segment whose head overlaps bytes we already delivered)
                // and drain any now-contiguous out-of-order buffer (mirror
                // of the Established path). Only a fully-old segment is
                // discarded.
                const UInt32 seg_end = seq + payload_len;
                if (SeqLt(rcv_nxt_, seg_end)) {
                    const UInt32 trim_off = rcv_nxt_ - seq;
                    const UInt32 fresh = payload_len - trim_off;
                    const UInt32 prev_trim = rcv_nxt_;
                    rcv_nxt_ = seg_end;  // advance before callback (piggyback ACK)
                    if (0 == fresh || !recv_cb_ || recv_cb_(payload + trim_off, fresh)) {
                        // Fresh suffix delivered (or backpressure-free):
                        // the frontier already advanced past the segment's data.
                        while (!ooo_.empty()) {
                            TrimOooToFrontier();
                            auto it = ooo_.find(rcv_nxt_);
                            if (it == ooo_.end()) {
                                break;
                            }
                            const OutSeg& seg = it->second;
                            const bool fin = seg.fin;  // capture before erase (seg aliases the node)
                            if (0 == seg.data.size()) {
                                // Pure-FIN entry: consume without a recv_cb_
                                // (mirror of the in-order drain above).
                                ooo_.erase(it);
                                if (fin) {
                                    ++rcv_nxt_;
                                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                                    return true;
                                }
                                continue;
                            }
                            const UInt32 prev_drain = rcv_nxt_;
                            rcv_nxt_ += static_cast<UInt32>(seg.data.size());  // advance before callback
                            if (recv_cb_ && !recv_cb_(seg.data.data(), static_cast<UInt32>(seg.data.size()))) {
                                // Backpressure: drop this buffered segment
                                // (refund its bytes) and stop draining; the
                                // peer retransmits.
                                rcv_nxt_ = prev_drain;  // rollback
                                rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                                ArmWindowUpdateAck(now);
                                ooo_bytes_ -= static_cast<UInt32>(seg.data.size());
                                ooo_.erase(it);
                                break;
                            }
                            if (TcpState::kClosed == state_) {
                                // The recv handler aborted reentrantly: stop.
                                return false;
                            }
                            ooo_bytes_ -= static_cast<UInt32>(seg.data.size());
                            ooo_.erase(it);
                            if (fin) {
                                ++rcv_nxt_;
                                SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                                return true;
                            }
                        }
                    } else {
                        // Backpressure: the fresh suffix was not consumed -
                        // roll the frontier back; the peer retransmits.
                        rcv_nxt_ = prev_trim;
                        rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                    }
                }
                SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
            } else {
                // Out-of-order: buffer for reassembly, re-ACK (RFC 2018).
                // RFC 793 accepts only segments inside the receive window;
                // window-external data is dropped (never buffered) -
                // otherwise a forged far-future seq fills the ooo buffer and
                // starves real reassembly (mirror of the Established path).
                const UInt32 wnd_end = rcv_nxt_ + rcv_wnd_;
                if (SeqLt(seq, wnd_end) || seq == wnd_end) {
                    if ((ooo_bytes_ + payload_len) <= OooCapacity(window_)) {
                        // Same-key replacement must refund the old entry's bytes
                        // (mirror of the Established path) - a retransmitted
                        // segment with the same seq would otherwise double-count
                        // ooo_bytes_ and prematurely trip the 64 KiB cap.
                        auto existing = ooo_.find(seq);
                        if (existing != ooo_.end()) {
                            ooo_bytes_ -= static_cast<UInt32>(existing->second.data.size());
                        }
                        OutSeg entry;
                        entry.data.assign(payload, payload + payload_len);
                        // RFC 793: preserve the FIN bit for the drain - an
                        // out-of-order data+FIN combined segment must consume
                        // its FIN once the gap fills (mirror of Established).
                        entry.fin = has_fin;
                        // RFC 7323: remember the TSval so TsRecent advances
                        // when the gap fills (the drained segment is then
                        // in-order and anchors the PAWS check).
                        entry.ts_val = ts_val;
                        ooo_[seq] = std::move(entry);
                        ooo_bytes_ += payload_len;
                    }
                }
                SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
            }
            return false;  // no FIN consumed by this call
        }

        void TcpConn::SetCaState(Byte new_state) noexcept {
            if (cc_.ca_state == new_state) {
                return;
            }
            cc_.ca_state = new_state;
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->set_state) {
                cc_ops_->set_state(&cc_, new_state);
            }
        }

        void TcpConn::EndCwndReduction() noexcept {
            // Kernel tcp_end_cwnd_reduction (tcp_input.c:2669-2683), verbatim
            // in structure:
            //
            //   if (icsk_ca_ops->cong_control)
            //       return;
            //   if (tp->snd_ssthresh < TCP_INFINITE_SSTHRESH &&
            //       (icsk_ca_state == TCP_CA_CWR || tp->undo_marker)) {
            //       tcp_snd_cwnd_set(tp, tp->snd_ssthresh);
            //   }
            //   tcp_ca_event(sk, CA_EVENT_COMPLETE_CWR);
            //
            // Three guards matter and all three were missing from the
            // dfe0b55 exit block:
            //
            //   1. cong_control: a rate-based algorithm owns the window
            //      (KCC/BBR compute it from the rate sample). The kernel does
            //      not touch cwnd for them - and does not even dispatch the
            //      event. Writing cwnd = snd_ssthresh here would hand KCC
            //      0x7FFFFFFF (KccSsthresh passes the sentinel through,
            //      cc_kcc.cpp:1042) which then only survives until the next
            //      KccMain clamps it to the BDP target: the pre-recovery
            //      window is lost (audit D01).
            //
            //   2. snd_ssthresh < TCP_INFINITE_SSTHRESH: the sentinel means
            //      "no reduction was ever recorded"; collapsing cwnd to it is
            //      the 0x7FFFFFFF window.
            //
            //   3. state == CWR || the episode was not undone: only an episode
            //      that actually reduced the window ends at ssthresh. A
            //      Recovery episode that was undone keeps prior_cwnd_ instead.
            //
            // The port's undo_marker_ cannot express the kernel's
            // `tp->undo_marker` here: the SACK entry sets it false (no undo
            // candidate), which would disable the collapse for every
            // SACK-confirmed recovery (review batch1 defect 2). episode_undone_
            // tracks the kernel's "undo_marker == 0" exactly: false while the
            // episode still stands, true once an undo restored the window.
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->cong_control) {
                return;   // rate-based CC owns cwnd (kernel: early return)
            }
            if (cc_.snd_ssthresh < 0x7FFFFFFFu &&
                (2 == cc_.ca_state || !episode_undone_)) {
                cc_.snd_cwnd = cc_.snd_ssthresh;
            }
            // Kernel tcp_ca_event(CA_EVENT_COMPLETE_CWR): the episode is over,
            // the CC may leave its "in recovery" bookkeeping (CUBIC's
            // in_recovery, an out-of-tree port's epoch marker).
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->cwnd_event) {
                cc_ops_->cwnd_event(&cc_, cc::kCaEventCompleteCwr);
            }
        }

        bool TcpConn::TcpMayUndo(const TcpOpts* opts) noexcept {
            // Kernel tcp_may_undo (tcp_input.c:2530-2533):
            //   return tp->undo_marker &&
            //          (!tp->undo_retrans || tcp_packet_delayed(tp));
            //
            // Port adaptation (see the batch-2 preamble in designA4_fix.md):
            // the port omits TSopt on data segments by design (tcp_fsm.cpp:
            // 999-1004, 2351-2357), so tcp_packet_delayed can never produce
            // valid evidence here. The kernel's INTENT is "do not undo while
            // retransmissions are still in flight - their D-SACKs may yet prove
            // the cut was wrong". That is exactly undo_retrans_ > 0:
            //
            //   undo_retrans_ == -1  nothing was retransmitted at entry
            //                        (kernel `retrans_out ?: -1`): the port's
            //                        documented no-SACK clean-exit undo applies.
            //   undo_retrans_ == 0   every retransmission was already ACKed:
            //                        undo is safe.
            //   undo_retrans_  > 0   a retransmission is still outstanding:
            //                        refuse (conservative; the kernel would only
            //                        allow it with TSopt evidence we cannot get).
            (void)opts;
            if (!undo_marker_) {
                return false;
            }
            return undo_retrans_ <= 0;
        }

        void TcpConn::CutCwnd() noexcept {
            // Kernel tcp_enter_loss (tcp_input_66.c:2154-2178) computes the
            // reduction in two steps:
            //   ssthresh = icsk_ca_ops->ssthresh(sk)   (Reno: max(cwnd >> 1, 2))
            //   cwnd     = tcp_packets_in_flight(tp) + 1
            // The two use DIFFERENT bases: ssthresh follows the WINDOW, cwnd
            // follows the live pipe. The port used packets_in_flight/2 for
            // both, which under a lost-head RTO (the head is marked lost
            // before the cut) halves an already-reduced number.
            //
            // tcp_packets_in_flight() is read LIVE, not from the cached
            // cc_.inflight: SACKed and LOST bytes have left the network, and
            // cc_.inflight is only refreshed on transmit (audit B5-D3).
            const UInt32 pipe_bytes = PipeInFlightBytes();
            // Kernel tcp_reno_ssthresh: max(cwnd >> 1, 2) (tcp_cong_66.c).
            UInt32 ssthresh = cc_.snd_cwnd >> 1;
            if (ssthresh < 2) {
                ssthresh = 2;
            }
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->ssthresh) {
                // Kernel tcp_enter_loss order (tcp_input.c:2168-2174):
                //   prior_ssthresh = current ssthresh
                //   prior_cwnd     = current cwnd
                //   ssthresh       = ops->ssthresh()
                //   cwnd           = packets_in_flight + 1
                // Only plugins that install an ssthresh hook take this path;
                // Reno/BBR/CUBIC-absent-hook keeps the RFC 5681 branch below
                // (their published behaviour is unchanged).
                cc_.prior_ssthresh = cc_.snd_ssthresh;
                cc_.prior_cwnd = cc_.snd_cwnd;
                cc_.snd_ssthresh = cc_ops_->ssthresh(&cc_);
                // Loss event (kernel tcp_enter_loss dispatches CA_EVENT_LOSS
                // after the ssthresh hook).
                if (NULLPTR != cc_ops_->cwnd_event) {
                    cc_ops_->cwnd_event(&cc_, cc::kCaEventLoss);
                }
                const UInt32 inflight_now = (pipe_bytes + peer_mss_ - 1) / peer_mss_;
                cc_.snd_cwnd = (0 < inflight_now) ? inflight_now + 1 : 1;
            } else {
                cc_.snd_ssthresh = ssthresh;
                if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->cwnd_event) {
                    cc_ops_->cwnd_event(&cc_, cc::kCaEventLoss);
                }
                if (cc_.snd_cwnd > cc_.snd_ssthresh) {
                    cc_.snd_cwnd = cc_.snd_ssthresh;
                }
                if (1 > cc_.snd_cwnd) {
                    cc_.snd_cwnd = 1;
                }
            }
            cc_.snd_cwnd_cnt = 0;
            // Kernel tcp_init_undo (tcp_input.c:2106-2111): remember how many
            // retransmissions are still in flight so tcp_may_undo can require
            // TSopt evidence before undoing. -1 = "nothing retransmitted".
            undo_retrans_ = (retrans_out_pkts_ > 0)
                ? static_cast<Int32>(retrans_out_pkts_) : -1;
            // A fresh cwnd-reduction episode: nothing has been undone yet.
            // CutCwnd is the common entry for the dup-ACK, RACK and RTO paths
            // (kernel tcp_init_undo is called from tcp_enter_loss /
            // tcp_enter_recovery), so this one write covers all three.
            episode_undone_ = false;
        }

        void TcpConn::RetransmitEarliestMissing(TimePoint now, const TcpOpts* opts) noexcept {
            // RFC 6675-style SACK recovery: retransmit the earliest missing
            // segment. The missing ranges are the gaps between the SACK
            // blocks (plus the front gap below the first block). Without
            // SACK blocks (or when the peer never sends SACK), the front is
            // the only candidate.
            if (retrans_queue_.empty()) {
                return;
            }
            const UInt32 mss = peer_mss_;
            UInt32 missing = 0;
            if (NULLPTR != opts && 0 < opts->sack_count) {
                // Find the missing range that contains sack_retx_next_.
                // Normalize each SACK edge into [base, base + 2^32) (RFC 1982
                // rotation, UInt64 arithmetic): an edge numerically below the
                // base is wrapped +2^32. This handles a block that straddles
                // the 2^32 boundary - e.g. [0xFFFFFFF0, 0x20) when snd_una_ is
                // 0 - correctly; a block wholly beyond the wrap (both edges
                // numerically below base but ordered after it) is an extreme
                // corner case the walk treats conservatively. A raw-order walk
                // treats a straddling block as a huge forward jump, misses the
                // real front gap, and pins `missing` inside already-SACKed
                // data (wasted retransmit, true losses deferred to the RTO).
                const UInt32 base = snd_una_;
                const UInt64 kWrap = 1ull << 32;
                UInt64 cursor = static_cast<UInt64>(base);
                UInt64 retx;
                if (0 == sack_retx_next_ || SeqLt(sack_retx_next_, base)) {
                    // Unset, or a stale pointer behind the frontier: start at
                    // the current gap's start (snd_una_).
                    retx = static_cast<UInt64>(base);
                } else {
                    retx = static_cast<UInt64>(sack_retx_next_);
                }
                const Byte n = opts->sack_count;
                for (Byte b = 0; b < n; ++b) {
                    const UInt32 raw_left = opts->sack[b][0];
                    const UInt32 raw_right = opts->sack[b][1];
                    const bool left_past = SeqLt(raw_left, base);
                    const bool right_past = SeqLt(raw_right, base);
                    if (left_past && right_past) {
                        continue;  // wholly behind the frontier: already ACKed
                    }
                    UInt64 left = left_past ? (static_cast<UInt64>(raw_left) + kWrap) : static_cast<UInt64>(raw_left);
                    UInt64 right = right_past ? (static_cast<UInt64>(raw_right) + kWrap) : static_cast<UInt64>(raw_right);
                    if (left > right) {
                        // Block crosses the wrap point: the [left, 2^32) prefix
                        // is already cumulatively ACKed; only [base, right)
                        // carries new confirmation.
                        left = static_cast<UInt64>(base);
                    }
                    if (retx < cursor) {
                        // sack_retx_next_ lies inside (or before) an earlier
                        // SACK block (stale, or landed exactly on a block's
                        // left edge after a single-segment gap retransmit):
                        // jump to the current gap's start - never retransmit
                        // already-received data (RFC 6675 �?.
                        missing = static_cast<UInt32>(cursor);
                        break;
                    }
                    if (retx < left) {
                        // The next target lies in [cursor, left): retransmit it.
                        missing = static_cast<UInt32>(retx < cursor ? cursor : retx);
                        break;
                    }
                    cursor = right;
                }
                if (0 == missing) {
                    // Beyond every SACK block: resume the walk at the open
                    // tail (the last block's edge, or sack_retx_next_ when
                    // already past it). The tail is in flight, not confirmed
                    // lost, but re-sending it keeps the peer's duplicate-ACK
                    // stream alive (which drives the window flush during
                    // recovery); the RTO backstop dedups genuinely live data.
                    missing = static_cast<UInt32>(retx < cursor ? cursor : retx);
                }
            }
            if (0 == missing) {
                missing = snd_una_;  // front
            }
            // Bounded candidate loop (at most TWO passes): the SACK-derived
            // missing point, then - exactly once - the queue front. The old
            // implementation RECURSED here with sack_retx_next_ = 0; when the
            // SACK walk produced a missing point that no queued segment covered
            // (a DSACK-only dup-ACK: the range was already popped), the recursion
            // recomputed the identical point and never terminated (Release: tight
            // loop, Debug: stack overflow).
            for (UInt32 attempt = 0; attempt < 2; ++attempt) {
                // Find the queued segment covering the missing sequence.
                for (SentSeg& seg : retrans_queue_) {
                    if (!SeqLt(missing, seg.seq) && SeqLt(missing, seg.seq + seg.len)) {
                        // RFC 1122 �?2.2.17: the retransmission must fit the
                        // peer's advertised window. A zero window takes no data -
                        // skip the transmit and wait for a window-opening ACK (the
                        // persist probe, when armed, re-arms the RTO path).
                        if (0 == snd_wnd_) {
                            return;
                        }
                        // RFC 6675 �? retransmit ONLY the missing interval, not
                        // the whole queued segment. When the missing point lies
                        // inside the segment, the prefix [seg.seq, missing) is
                        // already SACKed/delivered - resending it makes the peer
                        // drop the partially-overlapping segment (including the
                        // fresh suffix [missing, seg.seq+seg.len)), so the missing
                        // bytes never arrive (retransmission storm + corruption).
                        // Rebuild the packet to start at `missing` with a payload
                        // offset; the window trickle below handles the length.
                        const UInt32 seg_off = missing - seg.seq;
                        const UInt32 avail = seg.len - seg_off;
                        const UInt32 tx_len = (avail < snd_wnd_) ? avail : snd_wnd_;
                        // Storm gate: a dupack that carries NO new SACK information
                        // must not re-send the exact range already retransmitted
                        // (the peer answers each duplicate with another dupack ->
                        // a self-sustaining retransmit storm; observed 55k
                        // retransmits for a 1MB echo against a real kernel).
                        // A genuine re-loss is recovered by the RTO backstop
                        // (RetransmitFront), which bypasses this gate.
                        if (missing == last_retx_seq_ && tx_len == last_retx_len_) {
                            sack_retx_next_ = missing + tx_len;  // keep the walk position
                            return;
                        }
                        buf::BufRef copy;
                        if (0 == seg_off && seg.len == tx_len) {
                            // Rebuild the segment (SACK fast-retransmit). NOTE:
                            // the rebuild does NOT carry the TSopt - this stack
                            // sends the TSopt only on ACK segments (and the RTO
                            // retransmit, RetransmitFront fresh_ts), so the
                            // peer's PAWS check never applies to these rebuilds
                            // (a retransmission without a TSopt passes the
                            // timestamps_ok_ gate untouched).
                            const buf::BufRef& orig = seg.data;
                            const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                            const UInt32 tcp_hdr_len = static_cast<UInt32>(orig.Data()[ip_hdr_len + 12] >> 4) * 4;
                            // Keep the original PSH/URG bits on the rebuild (RFC
                            // 1011 PUSH semantics - a PSH-less retransmit would
                            // silently turn a pushed tail into an unpushed one).
                            const Byte orig_flags = orig.Data()[ip_hdr_len + 13];
                            const UInt16 retx_flags =
                                static_cast<UInt16>(kFlagAck | (cwr_pending_ ? kFlagCwr : 0) |
                                                    (orig_flags & (kFlagPsh | kFlagUrg)));
                            copy = BuildSegmentPacket(local_, remote_, seg.seq, rcv_nxt_,
                                                      retx_flags,
                                                      orig.Data() + ip_hdr_len + tcp_hdr_len, seg.len,
                                                      AdvertisedWindow(), rcv_wscale_,
                                                      Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                        } else {
                            // Partial retransmit (RFC 6675) or window trickle:
                            // rebuild the packet truncated/offset to
                            // [missing, missing + tx_len).
                            // seg.data stays alive in retrans_queue_ during the
                            // rebuild - read it in place (no Clone), mirroring the
                            // window-trickle path in RetransmitFront.
                            const buf::BufRef& orig = seg.data;
                            if (!orig.IsEmpty()) {
                                const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                                const UInt32 tcp_hdr_len = static_cast<UInt32>(orig.Data()[ip_hdr_len + 12] >> 4) * 4;
                                copy = BuildSegmentPacket(local_, remote_, missing, rcv_nxt_,
                                                          kFlagAck,
                                                          orig.Data() + ip_hdr_len + tcp_hdr_len + seg_off, tx_len,
                                                          AdvertisedWindow(), rcv_wscale_,
                                                          Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                            }
                        }
                        if (!copy.IsEmpty() && sink_) {
                            // Kernel tcp_event_data_sent runs INSIDE
                            // __tcp_transmit_skb, before tcp_retransmit_skb adds
                            // retrans_out (tcp_output_v66.c:3383): snapshot the
                            // TX_START gate before this retransmission is counted.
                            const bool pipe_empty = (0 == PipeInFlightBytes());
                            // D20 reentrancy guard: update ALL
                            // `seg` fields BEFORE the sink_ call. sink_ (EmitLocked)
                            // can re-enter this connection (Tx -> peer stack ->
                            // OnSegment -> OnAckReceived -> RetransmitEarliestMissing,
                            // recursive syncobj_): the nested call may pop_front
                            // retrans_queue_, invalidating the outer loop's `seg`
                            // reference. Everything touching `seg` must therefore
                            // complete first; sink_ only needs the moved `copy`.
                            ++retransmit_count_;
                            const Byte old_is_retrans = seg.is_retrans;
                            ++seg.retries;
                            // Loss signal: mark the segment's bytes lost on its
                            // FIRST retransmit only (kernel semantics: "lost" =
                            // newly marked lost since the last ACK). Repeated
                            // retransmits of the same segment must not re-deduct
                            // cwnd; reported once on the next rate sample.
                            if (1 == seg.retries) {
                                cc_.lost += tx_len;
                                // Packet-domain twin (see RetransmitFront).
                                cc_.lost_pkts += PktCount(tx_len, peer_mss_);
                            }
                            // Karn (RFC 6298): never RTT-sample a retransmitted
                            // segment (the ACK is ambiguous), or srtt/min_rtt (and
                            // the BDP derived from it) inflate.
                            seg.sent_at = 0;
                            seg.sent_delivered = cc_.delivered;
                            seg.sent_delivered_pkts = cc_.delivered_pkts;
                            seg.pkt_count = PktCount(seg.len, peer_mss_);
                            seg.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                            seg.is_retrans = 1;
                            // TCPCB_SACKED_RETRANS is now set (0 -> 1 on the
                            // first retransmit): refresh the pipe term.
                            PipeReaccountSeg(seg, seg.sacked, seg.lost, old_is_retrans);
                            sack_retx_next_ = missing + tx_len;  // next byte of the same gap
                            last_retx_seq_ = missing;  // storm gate: remember the emitted range
                            last_retx_len_ = tx_len;
                            // RFC 2883: remember the retransmitted range for the
                            // D-SACK undo. Unlike last_retx_* (storm gate, reset on
                            // a fresh cumulative ACK), this persists so a duplicate
                            // arriving in the SAME ACK that acknowledges the
                            // retransmission - or after it - still overlaps and the
                            // spurious cut can be undone.
                            dsack_retx_seq_ = missing;
                            dsack_retx_len_ = tx_len;
                            // Keep the RTO deadline fresh while SACK recovery makes
                            // progress; otherwise the RTO fires mid-recovery, cuts
                            // the window to 1 and aborts the retransmit chain.
                            ArmRetransmit(now);
                            // Kernel tcp_event_data_sent runs INSIDE
                            // __tcp_transmit_skb, before tcp_retransmit_skb adds
                            // retrans_out (tcp_output_v66.c:3383): the gate uses
                            // the snapshot taken above.
                            NotifyTxStart(pipe_empty);
                            // Kernel TCPCB_SACKED_RETRANS: retrans_out counts
                            // packets actually retransmitted and still in flight;
                            // lost_out is untouched here.
                            retrans_out_pkts_ += seg.pkt_count;
                            // Kernel tcp_retransmit_skb (tcp_output_66.c:3325):
                            // tp->total_retrans += tcp_skb_pcount(skb).
                            total_retrans_pkts_ += seg.pkt_count;
                            // Kernel tcp_output_66.c:3461-3462: a retransmission
                            // spends PRR credit as well (tcp_xmit_retransmit_queue
                            // does `tp->prr_out += tcp_skb_pcount(skb)` while the
                            // connection is in cwnd reduction). See the note in
                            // RetransmitFront (audit review batch 4, D).
                            if (fast_recovery_) {
                                prr_out_ += seg.pkt_count;
                            }
                            // Kernel tcp_output_66.c:3390-3392: every
                            // retransmission that leaves the wire increments
                            // undo_retrans (see the note in RetransmitFront).
                            if (undo_retrans_ < 0) {
                                undo_retrans_ = 0;
                            }
                            undo_retrans_ += static_cast<Int32>(seg.pkt_count);
                            // Emit LAST: the nested reentry (above) must observe a
                            // consistent (already-updated) retransmit state.
                            sink_(std::move(copy));
                        }
                        return;
                    }
                }
                // No queued segment covers this candidate.
                if (0 != attempt || !SeqLt(snd_una_, missing)) {
                    sack_retx_next_ = 0;
                    return;
                }
                // Fall back to the front ONCE so recovery still makes progress.
                sack_retx_next_ = 0;
                missing = snd_una_;
            }
            (void)mss;
        }

        void TcpConn::RackDetectLoss(TimePoint now) noexcept {
            // RFC 8985 RACK: time-based loss detection. A segment is lost
            // when a LATER segment has been delivered (RACK.seq covers it)
            // and the reorder window has elapsed since it was sent - its ACK
            // is overdue beyond what reordering can explain. The verdict
            // replaces the 3-dup-ACK threshold for SACK connections (the
            // time-based signal is loss, not order). Enter recovery like the
            // dup-ACK path and retransmit the earliest missing segment.
            // Gate: a pending RTO episode owns the loss verdict until Eifel
            // has adjudicated it (rto_pending_), and CA_Loss is driven by
            // tcp_process_loss in the kernel (tcp_input.c:2845-2896), NOT by
            // tcp_enter_recovery. Entering Recovery from CA_Loss here would
            // overwrite prior_cwnd_/prior_ssthresh_ with the ALREADY-CUT
            // window and reset high_seq_ to a value the RTO episode did not
            // choose - the subsequent spurious-RTO undo then restores the
            // wrong window (audit D11).
            // CA_CWR is equally protected: kernel tcp_enter_recovery is guarded
            // by `!tcp_in_cwnd_reduction(sk)` (tcp_input_66.c:2834-2839), and
            // tcp_in_cwnd_reduction covers BOTH CWR and Recovery
            // (tcp_66.h:1245-1249). During CWR the reduction snapshot already
            // exists, so a RACK verdict must not run tcp_init_cwnd_reduction a
            // second time and halve ssthresh again (audit B).
            if (!sack_ok_ || 0 == rack_seq_ || fast_recovery_ ||
                2 == cc_.ca_state || 4 == cc_.ca_state || rto_pending_ ||
                retrans_queue_.empty()) {
                return;
            }
            bool lost = false;
            for (SentSeg& seg : retrans_queue_) {
                if (seg.sacked >= seg.len) {
                    continue;  // fully SACKed: delivered
                }
                if (!SeqLt(seg.seq, rack_seq_)) {
                    break;  // at/after the RACK anchor: not lost
                }
                // Kernel tcp_rack_detect_loss (tcp_recovery_66.c:53-88) walks
                // the WHOLE queue and marks every overdue skb - the loop's
                // `break` is the ORDERING cutoff above, not a stop after the
                // first verdict:
                //
                //     if (!tcp_skb_sent_after(tp->rack.mstamp, ...))
                //         break;                    // sent after the anchor
                //     remaining = tcp_rack_skb_timeout(tp, skb, reo_wnd);
                //     if (remaining <= 0) {
                //         tcp_mark_skb_lost(sk, skb);   // and keep scanning
                //         list_del_init(&skb->tcp_tsorted_anchor);
                //     }
                //
                // Marking only the first overdue segment leaves the rest of
                // the overdue flight inside packets_out, so
                // tcp_packets_in_flight() over-reports the pipe and the
                // recovery entry derives its window from an inflated flight
                // (audit D15).
                if (rack_time_ > seg.sent_at && rack_time_ - seg.sent_at > rack_reo_wnd_) {
                    lost = true;
                    // Kernel RACK loss marking (tcp_input.c tcp_mark_skb_lost
                    // -> TCPCB_LOST + tp->lost_out): the LOSS DECISION point
                    // is where lost_out grows, not the retransmit emit.
                    if (0 == seg.lost) {
                        seg.lost = 1;
                        lost_out_pkts_ += seg.pkt_count;
                        // LOST takes the segment out of the pipe.
                        PipeReaccountSeg(seg, seg.sacked, 0, seg.is_retrans);
                    }
                }
            }
            if (!lost) {
                return;
            }
            // Capture the pre-cut window BEFORE the cut so a D-SACK
            // (RFC 2883) can undo a spurious RACK verdict - capturing after
            // the cut would record the halved value and the undo would no-op.
            // First-save gate (mirror of the RTO path at tcp_fsm.cpp:1764):
            // a RACK entry during an episode that already owns prior_cwnd_
            // must not replace it (audit D11).
            if (!fast_recovery_ && !rto_pending_) {
                prior_cwnd_ = cc_.snd_cwnd;
                prior_ssthresh_ = cc_.snd_ssthresh;
            }
            // Kernel tcp_enter_recovery (tcp_input_66.c:2816-2839) calls
            // tcp_init_undo unconditionally (:2826), arming the undo candidate
            // for the episode:
            //
            //     tp->undo_marker  = tp->snd_una;
            //     tp->undo_retrans = tp->retrans_out ?: -1;
            //
            // RACK enters recovery through that same function, so a
            // RACK-driven episode IS undoable: a D-SACK proving the
            // retransmission was spurious must restore the window. The port
            // left undo_marker_ at whatever the previous episode left behind,
            // so once the D-SACK path was gated on it a RACK recovery could
            // never be undone (test_dsack: the duplicate was recognized but
            // the restore was refused).
            //
            // A SACK-verified gap is a real loss signal, which is why the
            // dup-ACK entry clears the marker for SACK-bearing ACKs
            // (:3961). RACK differs: its verdict is TIME-based, so a merely
            // reordered segment trips it exactly like a lost one - the
            // spurious case is live and the candidate must be armed.
            undo_marker_ = true;
            undo_retrans_ = (retrans_out_pkts_ > 0)
                ? static_cast<Int32>(retrans_out_pkts_) : -1;
            // A new episode owns its own RTO verdict: an RTO retrans_stamp left
            // over from an earlier episode must not be adjudicated against this
            // one (kernel clears retrans_stamp on the recovery entry paths).
            rto_pending_ = false;
            rto_retx_end_ = 0;
            retrans_stamp_ts_ = 0;
            // Route the cut through CutCwnd: the inline half-cut
            // here bypassed the CC plugin's ssthresh hook and kCaEventLoss -
            // dup-ACK (CutCwnd at OnAckReceived) and RTO (CutCwnd at
            // OnRetransmitTimer) both dispatch the plugin contract, so RACK
            // must too (the plugin's wmax/epoch/loss state must not drift).
            CutCwnd();
            SetCaState(3);   // kernel CA_Recovery
            // Kernel tcp_init_cwnd_reduction: tp->high_seq = tp->snd_nxt.
            high_seq_ = snd_nxt_;
            fast_recovery_ = true;
            // Mirror of the dup-ACK entry: PRR's flight-size anchor plus the
            // retransmission cursor (the earliest missing segment). PACKETS
            // (kernel tp->recover_fs = tcp_packets_in_flight), and the PRR
            // counters restart for this episode (kernel tcp_init_cwnd_reduction
            // clears prr_delivered/prr_out at EVERY recovery entry; audit D09:
            // this RACK entry used to leave the previous episode's counters in
            // place).
            recover_fs_ = PktCount(snd_nxt_ - snd_una_, peer_mss_);
            prr_delivered_ = 0;
            prr_out_ = 0;
            sack_retx_next_ = snd_una_;
            last_retx_seq_ = 0;  // storm gate: allow the entry retransmit
            last_retx_len_ = 0;
            RetransmitEarliestMissing(now, NULLPTR);
            ++rack_losses_;
        }

        void TcpConn::OnAckReceived(UInt32 ack, bool ece, TimePoint now, const TcpOpts* opts) noexcept {
            // An ACK beyond snd_nxt_ acknowledges data we never sent: the
            // peer is lying or the segment is stale garbage. Honor it and
            // snd_una_ would jump past snd_nxt_, making inflight wrap to a
            // huge value and blocking every flush. RFC 793 leaves this
            // undefined; Linux drops the ACK (tcp_ack: before(maybe in
            // flight) checks).
            if (SeqLt(snd_nxt_, ack)) {
                return;
            }
            // Kernel rs->prior_in_flight (tcp_input.c:3839): the in-flight
            // bytes BEFORE this ACK cleans the retransmission queue. The
            // PROBE_BW cycle-phase test consumes it. It is
            // tcp_packets_in_flight(), i.e. SACKed and LOST bytes are NOT in
            // the network (audit B5-D3): using the raw snd_nxt-snd_una
            // distance makes the DRAIN/cycle gates see an inflated pipe.
            const UInt64 prior_in_flight_bytes =
                static_cast<UInt64>(PipeInFlightBytes());
            // Delivery snapshot at ACK entry: a duplicate ACK whose only
            // progress is SACK/DSACK still advances tp->delivered in the
            // kernel (tcp_input.c:3879-3881), so the dup-ACK path must
            // emit a rate sample too (kernel tcp_rate_gen at :3939).
            const UInt64 delivered_bytes_at_entry = cc_.delivered;
            const UInt64 delivered_pkts_at_entry = cc_.delivered_pkts;
            // RFC 6675 pipe estimate: track SACKed bytes per queued segment
            // so the recovery path can compute the pipe (bytes actually in
            // the network) instead of using the inflated cwnd. Runs on every
            // ACK carrying SACK blocks (cumulative and duplicate alike).
            // Wrapped blocks (sr < sl in sequence space) are skipped: with a
            // 64KB window they cannot occur, and ignoring them is safe.
            if (NULLPTR != opts && 0 < opts->sack_count) {
                UInt32 sack_new_pkts = 0;
                // Kernel RFC 2883 DSACK: the first block covering data at or
                // below the cumulative frontier is a spurious retransmission
                // and is counted as delivered (tcp_dsack_seen adds dup_segs
                // to state->sack_delivered). dup_segs = DIV_ROUND_UP(len,mss)
                // when the block spans more than one MSS, else 1.
                // Kernel gate (tcp_dsack_seen, tcp_input.c:1027-1032):
                // tp->dsack_dups accumulates every DSACK attempt, but the
                // DSACK is SKIPPED (no delivery credit) when dsack_dups
                // exceeds tp->total_retrans - the sender never retransmitted
                // that much, so the spurious-retransmission claim is bogus
                // (repeated or forged stale SACK block). Without this gate a
                // peer repeating a block behind the cum-ACK credits phantom
                // delivery on every dup-ACK: tp->delivered inflates, the rate
                // sample reports bandwidth, and cwnd grows on a lossless link
                // (test_reorder_gate s2: cwnd 12->13 with zero real delivery).
                // Kernel tcp_dsack_seen (tcp_input_66.c:1009-1046) verbatim in
                // order:
                //   1. `if (!before(start_seq, end_seq)) return 0;`  - empty or
                //      reversed blocks are rejected FIRST, before any counter
                //      moves (so they cannot poison dsack_dups).
                //   2. seq_len = end_seq - start_seq;
                //   3. `if (seq_len > tp->max_window) return 0;` - dubious.
                //   4. dup_segs = DIV_ROUND_UP(seq_len, mss) (1 when short).
                //   5. tp->dsack_dups += dup_segs; `if (tp->dsack_dups >
                //      tp->total_retrans) return 0;` - the sender never
                //      retransmitted that much, so the spurious-retransmission
                //      claim is bogus (repeated or forged stale SACK block).
                //   6. state->sack_delivered += dup_segs.
                // total_retrans is the PACKET-domain counter
                // (tcp_output_66.c:3325 `tp->total_retrans += segs`), not the
                // number of retransmission events: one TSO retransmission is
                // several packets.
                const UInt32 ds_sl = opts->sack[0][0];
                const UInt32 ds_sr = opts->sack[0][1];
                // Kernel tcp_check_dsack (tcp_input_66.c:1274-1284) has TWO
                // arms that classify block 0 as a duplicate:
                //
                //     if (before(start_seq_0, ack_seq)) {
                //         ...                              // plain D-SACK
                //     } else if (num_sacks > 1) {
                //         end_seq_1   = sp[1].end_seq;
                //         start_seq_1 = sp[1].start_seq;
                //         if (after(end_seq_0, end_seq_1) ||
                //             before(start_seq_0, start_seq_1))
                //             return false;
                //         ...                              // DSACK of O-FO
                //     } else {
                //         return false;
                //     }
                //
                // The port only implemented the first arm, so a peer that
                // reports the duplicate as the FIRST of two blocks - the shape
                // Linux itself emits when the duplicated data is out of order
                // - was not recognized at all: the spurious retransmission was
                // never credited, dsack_dups never moved, and the D-SACK undo
                // could never fire (audit D17).
                const bool dsack_plain = SeqLt(ds_sl, ack);
                bool dsack_ofo = false;
                if (!dsack_plain && 1 < opts->sack_count) {
                    const UInt32 sl1 = opts->sack[1][0];
                    const UInt32 sr1 = opts->sack[1][1];
                    // block0 must sit INSIDE block1: !after(sr0, sr1) &&
                    // !before(sl0, sl1)  ->  sr0 <= sr1 && sl1 <= sl0.
                    if (!SeqLt(sr1, ds_sr) && !SeqLt(ds_sl, sl1)) {
                        dsack_ofo = true;
                    }
                }
                if ((dsack_plain || dsack_ofo) && SeqLt(ds_sl, ds_sr)) {
                    const UInt32 ds_len = ds_sr - ds_sl;
                    if (ds_len <= max_window_) {
                        const UInt32 dup_segs = (0 < peer_mss_ && ds_len > peer_mss_)
                            ? ((ds_len + peer_mss_ - 1) / peer_mss_) : 1u;
                        dsack_dups_ += dup_segs;
                        if (dsack_dups_ <= total_retrans_pkts_) {
                            sack_new_pkts += dup_segs;
                            // Kernel tcp_check_dsack (tcp_input_66.c:1296-1301):
                            //   if (tp->undo_marker && tp->undo_retrans > 0 &&
                            //       !after(end_seq_0, prior_snd_una) &&
                            //       after(end_seq_0, tp->undo_marker))
                            //       tp->undo_retrans =
                            //           max_t(int, 0, tp->undo_retrans - dup_segs);
                            //
                            // A D-SACK the peer ACCEPTED (all of tcp_dsack_seen's
                            // credibility gates passed - that is the enclosing
                            // branch) proves `dup_segs` of our retransmissions
                            // were spurious, so they stop counting as
                            // outstanding and stop blocking tcp_may_undo. The
                            // port only ever INCREMENTED undo_retrans_, so after
                            // the first retransmission the counter never came
                            // back down and the legitimate undo was shut out
                            // for the rest of the connection (audit D16).
                            //
                            // `!after(end_seq_0, prior_snd_una)`: the duplicate
                            // must sit at/below the PRE-ACK cumulative frontier.
                            // snd_una_ still holds that value here - the
                            // assignment runs later in OnAckReceived
                            // (tcp_fsm.cpp:3494), matching the kernel's
                            // `prior_snd_una = tp->snd_una` capture before the
                            // update (tcp_input_66.c:3790).
                            // `after(end_seq_0, undo_marker)`: the duplicate
                            // must cover data sent inside the episode being
                            // undone. The port's undo_marker_ is a bool (the
                            // kernel's is a sequence = the entry's snd_una,
                            // tcp_init_undo at :2108), so the sequence compare
                            // cannot be reproduced directly; the enclosing
                            // dsack_overlap check - the block must overlap a
                            // RETRANSMITTED segment - is the port's equivalent
                            // anchor, since only this episode's retransmissions
                            // can carry retries > 0 while undo_marker_ holds.
                            if (undo_marker_ && 0 < undo_retrans_ &&
                                !SeqLt(snd_una_, ds_sr)) {
                                undo_retrans_ = (undo_retrans_ > static_cast<Int32>(dup_segs))
                                    ? undo_retrans_ - static_cast<Int32>(dup_segs) : 0;
                            }
                            // Kernel tcp_sacktag_one (tcp_input_66.c:1370-1374),
                            // the SECOND undo_retrans decrement - and the one
                            // that governs a D-SACK covering data still in the
                            // retransmit queue (the tcp_check_dsack arm above
                            // only fires for data already forgotten, i.e. at or
                            // below the PRE-ACK cumulative frontier):
                            //
                            //     if (dup_sack && (sacked & TCPCB_RETRANS)) {
                            //         if (tp->undo_marker && tp->undo_retrans > 0 &&
                            //             after(end_seq, tp->undo_marker))
                            //             tp->undo_retrans =
                            //                 max_t(int, 0, tp->undo_retrans - pcount);
                            //         ...
                            //     }
                            //
                            // TCPCB_RETRANS marks a skb that HAS been
                            // retransmitted, which is the port's `retries > 0`
                            // (NOT `is_retrans`, the TCPCB_SACKED_RETRANS twin).
                            // `after(end_seq, undo_marker)`: undo_marker is the
                            // episode entry's snd_una, and every segment this
                            // episode retransmitted starts at or above it, so a
                            // DSACK overlapping one of them satisfies the test by
                            // construction.
                            if (undo_marker_ && 0 < undo_retrans_) {
                                for (const SentSeg& seg : retrans_queue_) {
                                    if (0 == seg.retries) {
                                        continue;
                                    }
                                    const UInt32 seg_end = seg.seq + seg.len;
                                    if (SeqLt(ds_sr, seg.seq)) {
                                        break;   // queue is seq-sorted
                                    }
                                    if (SeqLt(ds_sl, seg_end) && SeqLt(seg.seq, ds_sr)) {
                                        undo_retrans_ = (undo_retrans_ > static_cast<Int32>(seg.pkt_count))
                                            ? undo_retrans_ - static_cast<Int32>(seg.pkt_count) : 0;
                                        if (0 >= undo_retrans_) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                for (Byte b = 0; b < opts->sack_count; ++b) {
                    const UInt32 sl = opts->sack[b][0];
                    const UInt32 sr = opts->sack[b][1];
                    if (SeqLt(sr, sl)) {
                        continue;  // malformed or empty block
                    }
                    for (SentSeg& seg : retrans_queue_) {
                        // Early exit: the queue is seq-sorted, so once a
                        // segment starts at/after the block's right edge no
                        // later segment can overlap either (avoids a full
                        // O(N) scan per SACK block on large send buffers).
                        if (!SeqLt(seg.seq, sr)) {
                            break;
                        }
                        const UInt32 seg_end = seg.seq + seg.len;
                        const UInt32 lo = SeqLt(seg.seq, sl) ? sl : seg.seq;
                        const UInt32 hi = SeqLt(seg_end, sr) ? seg_end : sr;
                        if (SeqLt(lo, hi)) {
                            const UInt32 ov = hi - lo;
                            const UInt32 room = seg.len - seg.sacked;
                            const UInt32 add = (ov < room) ? ov : room;
                            if (0 < add) {
                                const UInt32 before = seg.sacked;
                                const Byte before_lost = seg.lost;
                                const Byte before_is_retrans = seg.is_retrans;
                                seg.sacked += add;
                                // Kernel tcp_sacktag_one counts a skb's pcount
                                // ONCE, on its transition to TCPCB_SACKED_ACKED
                                // (a later SACK block covering the same bytes
                                // adds nothing). xtcp tracks SACK coverage in
                                // bytes, so count the segment when it first
                                // becomes FULLY SACKed; a partially covered
                                // segment is not delivered yet.
                                if (before < seg.len && seg.len <= seg.sacked) {
                                    sack_new_pkts += PktCount(seg.len, peer_mss_);
                                    // Kernel tcp_sacktag_one retires the loss
                                    // and retransmission tags when the skb
                                    // becomes SACKED_ACKED (tcp_input_66.c:
                                    // 1392-1396 / 1414-1417):
                                    //   if (sacked & TCPCB_LOST) {
                                    //       sacked &= ~TCPCB_LOST;
                                    //       tp->lost_out -= pcount;
                                    //   }
                                    // and, for a skb that was both LOST and
                                    // SACKED_RETRANS, retrans_out -= pcount
                                    // as well. The old code only decremented
                                    // lost_out when the segment was popped, so
                                    // a SACKed loss stayed in lost_out forever
                                    // (app_limited cond4 lost_out<=retrans_out
                                    // never held again).
                                    if (0 != seg.lost) {
                                        seg.lost = 0;
                                        lost_out_pkts_ = (lost_out_pkts_ >= seg.pkt_count)
                                            ? lost_out_pkts_ - seg.pkt_count : 0;
                                        // Kernel clears TCPCB_SACKED_RETRANS
                                        // together with LOST: the retransmit
                                        // is no longer in flight.
                                        if (0 != seg.is_retrans &&
                                            0 == seg.retrans_out_retired) {
                                            seg.retrans_out_retired = 1;
                                            retrans_out_pkts_ = (retrans_out_pkts_ >= seg.pkt_count)
                                                ? retrans_out_pkts_ - seg.pkt_count : 0;
                                        }
                                    }
                                }
                                // seg.sacked (and possibly seg.lost) changed:
                                // refresh the O(1) pipe sums for this segment.
                                PipeReaccountSeg(seg, before, before_lost, before_is_retrans);
                            }
                        }
                    }
                }
                // Same accumulation point as the kernel's tcp_count_delivered,
                // and BEFORE the cumulative-ACK add below (kernel order).
                cc_.delivered_pkts += sack_new_pkts;
            }
            // Kernel tcp_rate_gen clears the app-limited marker on EVERY ACK
            // (tcp_rate_66.c:123-125), a SACK/DSACK-only duplicate ACK
            // included. This runs before the branch's flush so a segment the
            // ACK emits cannot carry a stale is_app_limited snapshot (A2/A3);
            // EmitRateSample re-runs it after the cumulative-ACK delivery add.
            ClearAppLimitedMarker();
            // RFC 8985 RACK: the most recently delivered segment anchors the
            // time-based loss detection. "Delivered" = acknowledged by the
            // cumulative ACK or SACKed. The anchor is the HIGHEST delivered
            // seq (delivery in order), its send time the RACK time; the
            // reorder window shrinks toward min-RTT/4 on every delivery
            // (RFC 8985 s4: a larger window tolerates reordering; each
            // delivered segment proves the network can deliver in order, so
            // the window tightens).
            if (sack_ok_) {
                UInt32 delivered_end = snd_una_;  // the cumulative frontier (before this ACK's snd_una_ update)
                if (NULLPTR != opts) {
                    for (Byte b = 0; b < opts->sack_count; ++b) {
                        if (SeqLt(delivered_end, opts->sack[b][1])) {
                            delivered_end = opts->sack[b][1];
                        }
                    }
                }
                if (SeqLt(rack_seq_, delivered_end) && snd_nxt_ != snd_una_) {
                    // Locate the delivering segment to confirm the frontier
                    // maps to a real queued segment; RACK.time is the
                    // DELIVERY time (RFC 8985: the time the RACK segment was
                    // delivered), so a lost segment's age is measured from
                    // its send time against the most recent delivery.
                    //
                    // Walk from the TAIL: the delivered frontier is normally
                    // the newest data, so this finds it in one or two steps
                    // instead of scanning the whole (up to ~850 segment) queue
                    // on every SACK-bearing ACK.
                    for (auto it = retrans_queue_.rbegin();
                         it != retrans_queue_.rend(); ++it) {
                        if (it->seq + it->len == delivered_end) {
                            rack_seq_ = delivered_end;
                            rack_time_ = now;
                            break;
                        }
                        // The queue is seq-ascending, so once a segment ends
                        // before the frontier no earlier one can match either.
                        if (SeqLt(it->seq + it->len, delivered_end)) {
                            break;
                        }
                    }
                    if (rack_seq_ == delivered_end) {
                        const UInt32 rtt_min = (0 < cc_.rtt_min_us) ? cc_.rtt_min_us
                            : ((0 < srtt_) ? srtt_ : 1000);
                        const UInt32 target = (rtt_min / 4 > 1000) ? (rtt_min / 4) : 1000;
                        rack_reo_wnd_ = (0 == rack_reo_wnd_) ? target
                            : ((target < rack_reo_wnd_) ? target : rack_reo_wnd_);
                    }
                }
            }
            // RFC 2883 D-SACK: the FIRST SACK block covering data AT or
            // BELOW the cumulative frontier is a duplicate - the peer
            // received a segment we had already delivered (typically our
            // own retransmission, or a reordered original that made it
            // after all). That proves a retransmission was SPURIOUS: restore
            // the pre-cut window (the Eifel analogue for fast recovery). The
            // block is compared against the ACK's own cumulative value (not
            // the still-stale snd_una_): a D-SACK riding in the same ACK that
            // advances the frontier must still be recognized. A duplicate is
            // only that when it covers data WE retransmitted - a zero-info
            // SACK block (the peer re-ACKing already-ACKed data on a
            // lossless reorder) has the same at/below-frontier shape but is
            // NOT a D-SACK: undoing on it would clear fast_recovery_ and let
            // every such dup re-trigger RACK recovery. The most recent retransmitted range is tracked
            // persistently (survives the cumulative ACK that acknowledges it).
            // The undo fires ONLY when the D-SACK block overlaps a
            // RETRANSMITTED segment (seg.retries > 0): the duplicate proves
            // that retransmission was spurious.
            if (sack_ok_ && NULLPTR != opts && 0 < opts->sack_count &&
                !SeqLt(ack, opts->sack[0][1]) && 0 < prior_cwnd_) {
                const UInt32 ds_l = opts->sack[0][0];
                const UInt32 ds_r = opts->sack[0][1];
                bool dsack_overlap = (0 != dsack_retx_len_) &&
                    SeqLt(ds_l, dsack_retx_seq_ + dsack_retx_len_) &&
                    SeqLt(dsack_retx_seq_, ds_r);
                if (!dsack_overlap) {
                    for (const SentSeg& seg : retrans_queue_) {
                        if (0 == seg.retries) {
                            continue;  // only retransmitted segments make duplicates
                        }
                        if (SeqLt(ds_r, seg.seq)) {
                            break;  // queue is seq-sorted: past the block
                        }
                        if (SeqLt(ds_l, seg.seq + seg.len) && SeqLt(seg.seq, ds_r)) {
                            dsack_overlap = true;
                            break;
                        }
                    }
                }
                // Kernel tcp_try_undo_dsack (tcp_input_66.c:2580-2592):
                //
                //     if (tp->undo_marker && !tp->undo_retrans) {
                //         ...
                //         tcp_undo_cwnd_reduction(sk, false);
                //         return true;
                //     }
                //     return false;
                //
                // The undo_marker gate is what makes an episode with a CONFIRMED
                // loss un-undoable. Ports set undo_marker_ false at every
                // confirmation point: an RTO (:1825), a SACK block inside a
                // no-SACK entry (:4035, the peer proved a real gap), an ECE
                // (:3174, congestion is proven) and the undo itself (:3133).
                // Without the gate a duplicate that merely happens to overlap a
                // retransmitted range restores the pre-cut window even after
                // the loss was confirmed - the connection re-inflates and
                // overshoots (audit D16).
                //
                // undo_retrans_ mirrors tp->undo_retrans; <= 0 means no
                // retransmission is still outstanding, so no D-SACK can
                // still turn out to be spurious (same helper the recovery
                // exit uses, see TcpMayUndo).
                if (undo_marker_ && undo_retrans_ <= 0 && dsack_overlap && !rto_pending_) {
                    // Gate: a D-SACK must not undo while an RTO
                    // is pending - the RTO's own window cut is Eifel's to
                    // adjudicate (ts_ecr vs rto_ts_val_ below). Unconditionally
                    // restoring here would pre-empt Eifel and undo a REAL-loss
                    // RTO reduction on the first duplicate that happens to
                    // overlap a retransmitted range.
                    cc_.snd_cwnd = (prior_cwnd_ > cc_.snd_cwnd) ? prior_cwnd_ : cc_.snd_cwnd;
                    if (prior_ssthresh_ > cc_.snd_ssthresh) {
                        cc_.snd_ssthresh = prior_ssthresh_;
                    }
                    undo_marker_ = false;
                    episode_undone_ = true;  // kernel tcp_undo_cwnd_reduction: undo_marker = 0
                    fast_recovery_ = false;
                    sack_retx_next_ = 0;
                    dup_acks_ = 0;
                    // Kernel tcp_try_undo_dsack -> tcp_undo_cwnd_reduction ->
                    // tcp_try_keep_open: the recovery is undone, so the CA
                    // state leaves Recovery (tcp_try_keep_open picks Open or
                    // Disorder; the port has no Disorder state, so Open).
                    if (3 == cc_.ca_state) {
                        SetCaState(0);
                    }
                    high_seq_ = 0;   // episode over: a stale high_seq_ would
                                     // re-fire the exit block on the next ACK
                    // No RTO verdict can outlive its episode.
                    rto_pending_ = false;
                    rto_retx_end_ = 0;
                    retrans_stamp_ts_ = 0;
                    ++dsack_undos_;
                }
            }
            // RFC 3168 s6.1.2: an ECE on a received segment signals
            // congestion in the forward path. With a CC plugin installed the
            // window response belongs to the plugin (audit M5): deliver
            // kCaEventEcnCe + run its ssthresh hook (kernel tcp_ecn_withdraw
            // semantics) instead of the inline Reno half-cut, which
            // previously bypassed the plugin contract and left the plugin's
            // state (CUBIC's wmax/epoch) inconsistent. The half-cut below is
            // the Reno-only path (no plugin). The once-per-RTT throttle and
            // the CWR echo are core behavior in both cases.
            //
            // Kernel tcp_fastretrans_alert part A (tcp_input.c:2986-2987):
            //   if (ece_ack) tp->prior_ssthresh = 0;
            // Congestion is PROVEN, so the episode may never be undone. The
            // port expressed that as "no undo candidate"; keep it as a
            // prior_ssthresh_ reset too so the undo branches' guard
            // (`prior_ssthresh_ > snd_ssthresh`) is a no-op afterwards. This
            // runs for EVERY ECE ACK, not only the throttled one: the kernel
            // does not throttle part A either.
            if (ece && ecn_active_) {
                prior_ssthresh_ = 0;
                undo_marker_ = false;
                undo_retrans_ = -1;
                // Congestion is proven: no RTO verdict from an earlier episode
                // may survive into the CWR episode.
                rto_pending_ = false;
                rto_retx_end_ = 0;
                retrans_stamp_ts_ = 0;
            }
            if (ece && ecn_active_ &&
                (0 == ecn_reduce_at_ || now - ecn_reduce_at_ >= srtt_)) {
                // Kernel tcp_enter_cwr (tcp_input.c:2686-2697):
                //   prior_ssthresh = 0;
                //   if (icsk_ca_state < TCP_CA_CWR) {
                //       undo_marker = 0;
                //       tcp_init_cwnd_reduction(sk);   // high_seq/prior_cwnd/prr_*
                //       tcp_set_ca_state(sk, TCP_CA_CWR);
                //   }
                // tcp_init_cwnd_reduction runs the ssthresh hook BEFORE the
                // state change (tcp_input.c:2629-2641), so the hook still sees
                // the pre-CWR state - keep that order below.
                const bool enter_cwr = (cc_.ca_state < 2);
                if (enter_cwr) {
                    // tcp_init_cwnd_reduction: snapshot the window BEFORE the
                    // cut, anchor the episode at snd_nxt and restart PRR.
                    prior_cwnd_ = cc_.snd_cwnd;
                    high_seq_ = snd_nxt_;
                    prr_delivered_ = 0;
                    prr_out_ = 0;
                    // PACKETS (kernel tp->recover_fs = tcp_packets_in_flight).
                    recover_fs_ = PktCount(snd_nxt_ - snd_una_, peer_mss_);
                    episode_undone_ = false;  // fresh CWR episode: no undo yet
                }
                if (NULLPTR != cc_ops_) {
                    if (NULLPTR != cc_ops_->cwnd_event) {
                        cc_ops_->cwnd_event(&cc_, cc::kCaEventEcnCe);
                    }
                    if (NULLPTR != cc_ops_->ssthresh) {
                        cc_.snd_ssthresh = cc_ops_->ssthresh(&cc_);
                    }
                    // The reduction: the plugin's ssthresh hook updates its
                    // own state (CUBIC wmax/epoch) and returns the new
                    // threshold, but the window itself is cut HERE (clamp to
                    // the threshold, like the loss path in CutCwnd). The
                    // cwnd_event above is a notification only - reducing
                    // inside it would double the cut.
                    if (cc_.snd_cwnd > cc_.snd_ssthresh) {
                        cc_.snd_cwnd = cc_.snd_ssthresh;
                    }
                    if (1 > cc_.snd_cwnd) {
                        cc_.snd_cwnd = 1;
                    }
                } else {
                    UInt32 half = cc_.snd_cwnd / 2;
                    if (half < 2) {
                        half = 2;
                    }
                    cc_.snd_ssthresh = half;
                    if (cc_.snd_cwnd > cc_.snd_ssthresh) {
                        cc_.snd_cwnd = cc_.snd_ssthresh;
                    }
                    if (1 > cc_.snd_cwnd) {
                        cc_.snd_cwnd = 1;
                    }
                    cc_.snd_cwnd_cnt = 0;
                }
                if (enter_cwr) {
                    // tcp_enter_cwr's tail: the state transition LAST, so the
                    // ssthresh hook observed the pre-CWR state (kernel order).
                    SetCaState(2);   // kernel tcp_set_ca_state(TCP_CA_CWR)
                }
                ecn_reduce_at_ = now;
                cwr_pending_ = true;
            }
            if (SeqLt(ack, snd_una_)) {
                // Stale ACK - but it may still carry a window update (e.g.
                // the peer's zero-window probe reply): flush buffered sends
                // against the freshly advertised window and stop probing
                // once the window is non-zero.
                if (0 < snd_wnd_) {
                    persist_deadline_ = 0;
                    persist_interval_ = persist_base_;  // restore user-configured base
                }
                if (0 < pending_send_.size()) {
                    FlushPendingSend(now);
                }
                return;
            }
            if (ack != snd_una_) {
                // RFC 3522 Eifel: adjudicate the pending RTO once the ACK
                // actually covers the retransmitted range (rto_retx_end_), or
                // once the queue drained (nothing left to judge).
                //
                // Kernel tcp_packet_delayed (tcp_input.c:2437-2441):
                //   retrans_stamp && tcp_tsopt_ecr_before(tp, retrans_stamp)
                // tcp_tsopt_ecr_before (tcp_input.c:2418-2422):
                //   saw_tstamp && rcv_tsecr && before(rcv_tsecr, when)
                // i.e. the RTO is spurious ONLY when the echoed TSval is
                // STRICTLY BEFORE the first retransmission's TSval. "Different"
                // is not enough: an ACK for data sent AFTER the RTO echoes a
                // NEWER TSval and must not undo a real loss (audit D03).
                //
                // Without TSopt the question cannot be answered positively, so
                // the verdict is "real loss" (no undo) - but it IS answered, so
                // rto_pending_ clears and the D-SACK gate reopens (audit D04).
                if (rto_pending_) {
                    const bool adjudicated =
                        (0 != rto_retx_end_ && !SeqLt(ack, rto_retx_end_)) ||
                        retrans_queue_.empty();
                    if (adjudicated) {
                        const bool have_ts = timestamps_ok_ && NULLPTR != opts &&
                                             opts->has_timestamp && 0 != opts->ts_ecr;
                        const bool spurious = have_ts && 0 != retrans_stamp_ts_ &&
                                              SeqLt(opts->ts_ecr, retrans_stamp_ts_);
                        if (spurious) {
                            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->undo_cwnd &&
                                0 != prior_cwnd_) {
                                cc_.snd_cwnd = cc_ops_->undo_cwnd(&cc_);
                            } else {
                                cc_.snd_cwnd = prior_cwnd_;
                            }
                            if (prior_ssthresh_ > cc_.snd_ssthresh) {
                                cc_.snd_ssthresh = prior_ssthresh_;
                            }
                            episode_undone_ = true;  // kernel tcp_undo_cwnd_reduction
                            // Kernel tcp_try_undo_loss (tcp_input_66.c:2608):
                            // a successful loss undo zeroes icsk_retransmits,
                            // so the next timeout is a fresh loss window and
                            // may cut ssthresh again. tcp_undo_cwnd_reduction
                            // itself does NOT touch it, which is why only this
                            // (RTO) path clears it.
                            icsk_retransmits_ = 0;
                        }
                        rto_pending_ = false;
                        rto_retx_end_ = 0;
                        retrans_stamp_ts_ = 0;
                        // Kernel tcp_try_undo_loss: a spurious RTO returns the
                        // CA state to Open (tcp_set_ca_state(TCP_CA_Open)).
                        // A REAL loss stays in CA_Loss - kernel tcp_process_loss
                        // keeps it there until snd_una reaches high_seq, and the
                        // episode-exit block closes it then. The old code
                        // cleared Loss on the first advancing ACK even when
                        // snd_una was still below high_seq, which let a second
                        // loss episode start from Open (audit D03/D04).
                        if (spurious && 4 == cc_.ca_state) {
                            SetCaState(0);
                            high_seq_ = 0;
                        }
                    }
                }
                // Cumulative ACK advanced: sample RTT from the oldest newly
                // acknowledged segment, then drop acknowledged segments.
                const UInt32 ack_advance = ack - snd_una_;
                // Kernel tcp_clean_rtx_queue takes prior_sacked = tp->sacked_out
                // at its ENTRY, after SACK tagging and BEFORE the pop.  A
                // segment that this very ACK cumulatively acknowledges may
                // still be SACKed here; scanning after the pop would miss it.
                // Only a sub-MSS advance can be a delayed ACK, so the O(queue)
                // scan is restricted to that case (usually the first segment
                // matches immediately).
                bool prior_sacked_out = false;
                if (0 < ack_advance && ack_advance < peer_mss_) {
                    for (const SentSeg& s : retrans_queue_) {
                        if (0 < s.sacked) {
                            prior_sacked_out = true;
                            break;
                        }
                    }
                }
                UInt32 popped_count = 0;
                UInt32 popped_pkts = 0;
                UInt32 newest_len = 0;
                UInt64 newest_sent_delivered = 0;
                UInt64 newest_sent_delivered_pkts = 0;
                Byte newest_app_limited = 0;
                batch_retrans_ = false;
                UInt32 rtt_sample = 0;
                // RFC 7323 RTTM: the peer's tsecr echoes our last tsval -
                // now - tsecr is a more precise RTT sample than the
                // sent_at-based one (it measures the whole round trip,
                // immune to delayed-ACK and send batching).
                if (timestamps_ok_ && NULLPTR != opts && opts->has_timestamp && 0 != opts->ts_ecr &&
                    (retrans_queue_.empty() || 0 == retrans_queue_.front().retries)) {
                    const UInt32 rtt_ms = static_cast<UInt32>(now / 1000 - opts->ts_ecr);
                    if (rtt_ms < (3600u * 1000)) {  // sanity: < 1 hour
                        rtt_sample = rtt_ms * 1000;
                    }
                }
                while (!retrans_queue_.empty()) {
                    SentSeg& front = retrans_queue_.front();
                    const UInt32 seg_end = front.seq + front.len;
                    if (SeqLt(seg_end, ack) || seg_end == ack) {
                        if (0 != front.sent_at && now >= front.sent_at) {
                            rtt_sample = static_cast<UInt32>(now - front.sent_at);
                        }
                        ++popped_count;
                        newest_len = front.len;
                        newest_app_limited = front.app_limited;
                        // Kernel tcp_clean_rtx_queue retires the per-skb tags:
                        //   TCPCB_LOST        -> lost_out    -= pcount
                        //   TCPCB_SACKED_RETRANS -> retrans_out -= pcount
                        if (0 != front.lost) {
                            lost_out_pkts_ = (lost_out_pkts_ >= front.pkt_count)
                                ? lost_out_pkts_ - front.pkt_count : 0;
                        }
                        if (0 != front.is_retrans && 0 == front.retrans_out_retired) {
                            retrans_out_pkts_ = (retrans_out_pkts_ >= front.pkt_count)
                                ? retrans_out_pkts_ - front.pkt_count : 0;
                        }
                        // Kernel tcp_clean_rtx_queue (tcp_input.c:3312-3315):
                        // a skb already SACKED_ACKED only decrements sacked_out;
                        // tcp_count_delivered runs for the NOT-yet-SACKed part
                        // only. Counting the full pkt_count here would charge
                        // the SACK-delivered bytes twice (once at tag time).
                        {
                            const UInt32 unsacked = front.len - front.sacked;
                            if (0 < unsacked) {
                                popped_pkts += PktCount(unsacked, peer_mss_);
                            }
                        }
                        if (front.sent_delivered > newest_sent_delivered) {
                            newest_sent_delivered = front.sent_delivered;
                        }
                        if (front.sent_delivered_pkts > newest_sent_delivered_pkts) {
                            newest_sent_delivered_pkts = front.sent_delivered_pkts;
                        }
                        // Kernel FLAG_RETRANS_DATA_ACKED is ORed over every
                        // skb cleaned by this ACK (not just the newest one).
                        if (0 != front.is_retrans) {
                            batch_retrans_ = true;
                        }
                        // Unaccount BEFORE the pop destroys the element (front
                        // is a reference into the deque).
                        PipeAccountSeg(front, -1);
                        retrans_queue_.pop_front();
                        if (retrans_queue_.empty()) {
                            first_outstanding_ = 0;  // nothing outstanding: the user-timeout clock resets
                        }
                        continue;
                    }
                    break;
                }
                const UInt32 acked = ack_advance;
                // Capture the pre-ACK pacing rate so any rate update below
                // (ACK-clock or CC plugin) can invalidate a stale deadline.
                const UInt64 old_rate = cc_.pacing_rate;
                if (0 < rtt_sample) {
                    UpdateRto(rtt_sample);
                    cc_.srtt_us = srtt_;
                    cc_.mdev_us = rttvar_;
                    if (0 == cc_.rtt_min_us || rtt_sample < cc_.rtt_min_us) {
                        cc_.rtt_min_us = rtt_sample;
                    }
                    // ACK-clock pacing: send one cwnd per RTT (bytes/sec).
                    // Rate-based algorithms (BBR/KCC) override this via their
                    // cong_control hook; Reno tracks the growing window.
                    if (NULLPTR == cc_ops_ && 0 < cc_.snd_cwnd && 0 < srtt_) {
                        const UInt64 cwnd_bytes = static_cast<UInt64>(cc_.snd_cwnd) * peer_mss_;
                        cc_.pacing_rate = (cwnd_bytes * 1000000ull) / srtt_;
                    }
                    // ACK-clock path (no CC plugin): a stale deadline computed
                    // from an older, smaller rate would gate sends for minutes.
                    // Reset whenever the rate actually changed.
                    if (cc_.pacing_rate != old_rate) {
                        pacing_deadline_ = 0;
                    }
                }
                snd_una_ = ack;
                dup_acks_ = 0;
                fast_retransmit_seq_ = 0;
                last_retx_seq_ = 0;  // storm gate: a fresh cumulative ACK resets the context
                last_retx_len_ = 0;
                // Kernel tcp_clear_retrans (tcp_input_66.c:3829) zeroes
                // icsk_retransmits once a cumulative ACK acknowledges data:
                // the next timeout starts a NEW loss window, so it may cut
                // ssthresh again.
                icsk_retransmits_ = 0;
                // RFC 8985 TLP: any cumulative ACK cancels the pending probe.
                tlp_armed_ = false;
                tlp_deadline_ = 0;
                // RFC 8985 RACK: the cumulative ACK updated the delivery
                // anchor (OnAckReceived); run the time-based loss detection
                // against the remaining gaps.
                RackDetectLoss(now);
                // Window recovered: stop zero-window probing (RFC 1122).
                if (0 < snd_wnd_) {
                    persist_deadline_ = 0;
                    persist_interval_ = persist_base_;  // reset the backoff to the user base
                }
                if (!retrans_queue_.empty()) {
                    ArmRetransmit(now);
                } else if ((TcpState::kFinWait1 == state_ || TcpState::kLastAck == state_ ||
                            TcpState::kClosing == state_) &&
                           snd_una_ == (snd_nxt_ - 1)) {
                    // The FIN (seq snd_nxt_-1) is the only byte in flight and
                    // it is NOT in retrans_queue_ (Close() sends it
                    // fire-and-forget). The data ACK that emptied the queue
                    // must not disarm the RTO: a lost FIN still needs
                    // OnRetransmitTimer's FinWait1/LastAck/Closing path to
                    // re-send it - disarming strands the close handshake
                    // forever (peer never ACKs, slot never released).
                    ArmRetransmit(now);
                } else {
                    rto_deadline_ = 0;
                }
                // Kernel ordering: tp->delivered/inflight advance BEFORE the
                // ACK-triggered output, so segments emitted by the flush carry
                // the post-ACK delivered snapshot (rate_sample tx.delivered).
                // Kernel tcp_packets_in_flight(tp) = packets_out - (sacked_out + lost_out)
                // + retrans_out (tcp_h_66.h:1198-1220). The raw snd_nxt-snd_una
                // distance counts SACKed and LOST bytes as in flight, so every
                // CC consumer (tcp_cwnd_reduction's cwnd = inflight + sndcnt,
                // KCC packet_conservation, BBR's bdp gate) saw an inflated
                // pipe during recovery (audit B5-D3 / B6-D1).
                cc_.inflight = PipeInFlightBytes();
                cc_.delivered += acked;
                // Packet-domain twin (kernel tp->delivered): pkts_acked is
                // the sum of tcp_skb_pcount over the cleaned skbs. The SACK
                // portion was already added above, before this (kernel order).
                cc_.delivered_pkts += (0 < popped_pkts) ? popped_pkts : 0;
                cc_.delivered_mstamp = now / 1000;
                // Kernel tcp_rate_gen: clear the app-limited marker once
                // delivered passes it (after() comparison, not a raw >).
                // The marker is latched in the PACKET domain, so the clear
                // test must read delivered_pkts (same domain).
                // NOTE: this clear now runs from EmitRateSample (the
                // tcp_rate_gen equivalent) on EVERY ACK, SACK/DSACK-only
                // duplicate ACKs included (tcp_rate_66.c:123-125).
                if (0 < popped_count) {
                    if (newest_sent_delivered > batch_prior_delivered_) {
                        batch_prior_delivered_ = newest_sent_delivered;
                    }
                    if (newest_sent_delivered_pkts > batch_prior_delivered_pkts_) {
                        batch_prior_delivered_pkts_ = newest_sent_delivered_pkts;
                    }
                    batch_app_limited_ = newest_app_limited;
                }
                last_ack_delayed_ = cc::IsLikelyDelayedAck(
                    acked, popped_count, newest_len, batch_retrans_, prior_sacked_out,
                    ece, (NULLPTR != opts && 0 < opts->sack_count),
                    newest_sent_delivered, cc_.delivered, peer_mss_);
                // Kernel tcp_fastretrans_alert part D (tcp_input.c:2996-3020):
                // an episode ends when snd_una reaches high_seq. The CA state
                // MUST return to CA_Open BEFORE the CC hook runs (the kernel
                // runs tcp_fastretrans_alert first, then tcp_rate_gen +
                // tcp_cong_control), and the window handling must follow
                // tcp_end_cwnd_reduction's guards instead of an unconditional
                // `cwnd = ssthresh` (audit D01/D13).
                if (0 != high_seq_ && !SeqLt(snd_una_, high_seq_)) {
                    if (2 == cc_.ca_state) {
                        // Kernel part D, case TCP_CA_CWR (tcp_input.c:3003-3010):
                        // CWR is held until something ABOVE high_seq is ACKed
                        // (that is when the receiver has actually seen our CWR
                        // bit). At exactly high_seq the episode stays open.
                        // tcp_end_cwnd_reduction runs FIRST, while the state is
                        // still CWR (the event observes state 2), then Open.
                        if (snd_una_ != high_seq_) {
                            EndCwndReduction();
                            SetCaState(0);
                            high_seq_ = 0;
                            // No RTO verdict can outlive its episode.
                            rto_pending_ = false;
                            rto_retx_end_ = 0;
                            retrans_stamp_ts_ = 0;
                        }
                    } else if (3 == cc_.ca_state) {
                        // Kernel part D, case TCP_CA_Recovery (tcp_input.c:
                        // 3012-3018): tcp_try_undo_recovery runs first
                        // (tcp_input.c:2551-2577) - may_undo restores the
                        // window and sets the state to Open - and only then
                        // does tcp_end_cwnd_reduction fire, so the
                        // COMPLETE_CWR event observes CA_Open.
                        //
                        // Reno holds the episode at exactly high_seq
                        // (tcp_is_non_sack_preventing_reopen, tcp_input.c:
                        // 2535-2548): reopening there lets the very next
                        // dup-ACK start a false fast retransmit (RFC 2582).
                        // The undo still runs on that ACK - only the episode
                        // end (state change + end_cwnd_reduction) is skipped.
                        const bool hold_reno = (snd_una_ == high_seq_) && !sack_ok_;
                        if (fast_recovery_) {
                            // Linux tcp_try_undo_recovery: tcp_may_undo()
                            // decides between "restore the pre-cut window" and
                            // "the reduction stands".
                            if (TcpMayUndo(opts)) {
                                if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->undo_cwnd &&
                                    0 != prior_cwnd_) {
                                    cc_.snd_cwnd = cc_ops_->undo_cwnd(&cc_);
                                } else {
                                    cc_.snd_cwnd = prior_cwnd_;
                                }
                                if (prior_ssthresh_ > cc_.snd_ssthresh) {
                                    cc_.snd_ssthresh = prior_ssthresh_;
                                }
                                undo_marker_ = false;
                                episode_undone_ = true;  // kernel tcp_undo_cwnd_reduction
                            }
                            if (!hold_reno) {
                                fast_recovery_ = false;
                                sack_retx_next_ = 0;
                                undo_retrans_ = -1;
                            }
                        }
                        if (!hold_reno) {
                            // Kernel tcp_try_undo_recovery -> tcp_set_ca_state
                            // (TCP_CA_Open) at tcp_input.c:2574, i.e. BEFORE
                            // tcp_end_cwnd_reduction at :3017.
                            SetCaState(0);
                            EndCwndReduction();
                            high_seq_ = 0;
                            // No RTO verdict can outlive its episode.
                            rto_pending_ = false;
                            rto_retx_end_ = 0;
                            retrans_stamp_ts_ = 0;
                        }
                        // hold_reno: tcp_is_non_sack_preventing_reopen keeps the
                        // state, fast_recovery_, high_seq_ and the reduction
                        // bookkeeping. The undo above already ran (and cleared
                        // its candidate); when there was nothing to undo the
                        // candidate is left alone - a later DSACK may still
                        // undo (kernel does not clear undo_marker here either).
                    } else if (4 == cc_.ca_state) {
                        // Kernel tcp_process_loss ends with
                        //   tcp_try_undo_recovery(sk);
                        //   return;                              (tcp_input.c:2881-2885)
                        // i.e. NO tcp_end_cwnd_reduction: neither a
                        // `cwnd = ssthresh` collapse nor CA_EVENT_COMPLETE_CWR.
                        //
                        // tcp_try_undo_recovery (tcp_input.c:2551-2577) then
                        // calls tcp_is_non_sack_preventing_reopen
                        // (tcp_input.c:2535-2548): a no-SACK Reno connection at
                        // exactly high_seq HOLDS the state (RFC 2582 - reopening
                        // there lets the next dup-ACK start a false fast
                        // retransmit). The Recovery branch above already holds
                        // (hold_reno); this Loss branch must do the same
                        // (audit D19). Without it the RTO episode closed one
                        // segment too early and the following dup-ACK re-entered
                        // a spurious fast recovery.
                        const bool hold_reno = (snd_una_ == high_seq_) && !sack_ok_;
                        if (!hold_reno) {
                            fast_recovery_ = false;
                            sack_retx_next_ = 0;
                            undo_retrans_ = -1;
                            SetCaState(0);
                            high_seq_ = 0;
                            // No RTO verdict can outlive its episode.
                            rto_pending_ = false;
                            rto_retx_end_ = 0;
                            retrans_stamp_ts_ = 0;
                        }
                    } else {
                        // Already Open (or Disorder): the episode marker is
                        // stale - drop it without touching the window.
                        high_seq_ = 0;
                        // No RTO verdict can outlive its episode.
                        rto_pending_ = false;
                        rto_retx_end_ = 0;
                        retrans_stamp_ts_ = 0;
                    }
                }
                // RFC 5681 window growth on the ACK clock.
                if (NULLPTR != cc_ops_) {
                    // Cumulative rate sample (kernel tcp_rate_gen semantics):
                    // cc_.delivered accumulates across ACKs; each emitted
                    // sample reports the delivered delta accumulated since the
                    // last sample over the elapsed wall time. The sample window
                    // opens on the first ACK and closes only when time has
                    // advanced past the previous sample - so same-tick ACK
                    // bursts accumulate into one sample instead of each being
                    // dropped as a ~0 interval (which under-reported the batch
                    // as one MSS over the whole interval, starving cwnd).
                    // KCC/BBR consume rs.delivered / rs.interval_us for
                    // bandwidth.
                    EmitRateSample(now, acked, rtt_sample, prior_in_flight_bytes, ack);
                    // Reset the pacing deadline ONLY when the CC plugin changed
                    // the rate: a stale deadline from an old (small) rate would
                    // gate sends for minutes. An unconditional reset would let
                    // every data ACK bypass the pacing gate, so a rate-based CC
                    // (BBR drain phase, KCC) would flush its whole buffer in
                    // one burst.
                    if (cc_.pacing_rate != old_rate) {
                        pacing_deadline_ = 0;
                    }
                } else {
                    // No plugin (Reno default): clear the loss accumulator so
                    // it cannot grow unbounded (there is no hook to report it).
                    // The packet-domain twin must be cleared with it, or it
                    // keeps accumulating forever on a Reno flow.
                    cc_.lost = 0;
                    cc_.lost_pkts = 0;
                    if (cc_.snd_cwnd < cc_.snd_ssthresh) {
                        // Slow start: one segment per segment acknowledged,
                        // clamped so snd_cwnd never overshoots ssthresh - an
                        // unbounded slow start (ssthresh starts at
                        // 0x7FFFFFFF, only loss lowers it) lets the
                        // cwnd*MSS window product overflow UInt32 below and
                        // collapse the send window to a trickle.
                        cc_.snd_cwnd += (acked + peer_mss_ - 1) / peer_mss_;
                        if (cc_.snd_cwnd > cc_.snd_ssthresh) {
                            cc_.snd_cwnd = cc_.snd_ssthresh;
                        }
                    } else {
                        // Congestion avoidance (RFC 5681): add one segment per
                        // cwnd-bytes acknowledged. Classic byte counting via the
                        // snd_cwnd_cnt accumulator (kernel tcp_sock semantics);
                        // a naive "cwnd += acked/cwnd" mixes bytes with segments
                        // and explodes the window hundreds-fold.
                        cc_.snd_cwnd_cnt += acked;
                        const UInt64 cwnd_bytes = static_cast<UInt64>(cc_.snd_cwnd) * peer_mss_;
                        while (static_cast<UInt64>(cc_.snd_cwnd_cnt) >= cwnd_bytes) {
                            cc_.snd_cwnd_cnt -= static_cast<UInt32>(cwnd_bytes);
                            if (cc_.snd_cwnd < 0x7FFFFFFF) {
                                cc_.snd_cwnd += 1;
                            }
                        }
                    }
                }
                // RFC 6937 PRR (proportional rate reduction): the cwnd tracks
                // the delivered/out balance so the send rate stays proportional
                // to the recovery progress (fast recoveries complete fast, slow
                // ones stay bounded) - replacing the fixed ssthresh+3 inflation.
                //
                // Kernel tcp_cong_control (tcp_input.c:3513-3531) returns EARLY
                // for a cong_control algorithm:
                //   if (icsk_ca_ops->cong_control) { cong_control(sk, rs); return; }
                //   if (tcp_in_cwnd_reduction(sk)) tcp_cwnd_reduction(...);
                // i.e. KCC/BBR own cwnd during recovery; the FSM must not
                // overwrite it (audit D08).
                //
                // Kernel tcp_cwnd_reduction (tcp_input.c:2643-2667) is entirely
                // in PACKETS: sndcnt/delta/prior_cwnd/prr_delivered/prr_out.
                // The port used to add `acked` (BYTES) to a packet-domain
                // ssthresh, so a 2*MSS partial ACK produced cwnd = 2923
                // (audit D08).
                if (fast_recovery_ && (NULLPTR == cc_ops_ || NULLPTR == cc_ops_->cong_control)) {
                    prr_delivered_ += PktCount(acked, peer_mss_);
                    // Kernel TCP_INFINITE_SSTHRESH guard (same sentinel test as
                    // tcp_end_cwnd_reduction, tcp_input.c:2677): the sentinel
                    // means "no reduction was ever recorded", so it is NOT a
                    // window. The kernel's delta >= 0 branch computes
                    // cwnd = packets_in_flight + sndcnt and never uses the
                    // sentinel as an anchor; the port's simplified
                    // `ssthresh + delivered - out` would, which is how a held
                    // Reno episode ended at 0x7FFFFFFF (a4rev41/a4rev43[1]).
                    // Keep the window the caller (undo / CC) set instead.
                    if (cc_.snd_ssthresh < 0x7FFFFFFFu) {
                        const Int64 prr = static_cast<Int64>(cc_.snd_ssthresh) +
                            static_cast<Int64>(prr_delivered_) - static_cast<Int64>(prr_out_);
                        cc_.snd_cwnd = (prr < 1) ? 1 : static_cast<UInt32>(prr);
                    }
                    // RFC 6675 partial-ACK: stay in fast recovery while
                    // SACK-implied gaps remain after the cumulative ACK, so
                    // each newly recovered segment's ACK (a dupack for the
                    // next gap) retransmits the following missing segment.
                    // Exiting on the first partial ACK strands the rest of a
                    // loss burst behind the RTO backstop (which can explode
                    // to tens of seconds).
                    bool gaps_remain = false;
                    if (NULLPTR != opts && 0 < opts->sack_count) {
                        // Normalize SACK blocks into [ack, ack + 2^32)
                        // (RFC 1982 rotation, UInt64 arithmetic) so a peer
                        // block that wraps the 2^32 boundary is walked in the
                        // correct order; a raw-order walk misses the gap in
                        // front of a wrapped block and may spuriously clear
                        // fast recovery.
                        const UInt32 ack_base = ack;
                        constexpr UInt64 kWrap = 1ull << 32;
                        auto rot = [ack_base, kWrap = kWrap](UInt32 e) -> UInt64 {
                            return SeqLt(e, ack_base) ? (static_cast<UInt64>(e) + kWrap) : static_cast<UInt64>(e);
                        };
                        UInt64 cursor = static_cast<UInt64>(ack);
                        for (Byte b = 0; b < opts->sack_count; ++b) {
                            const UInt32 raw_left = opts->sack[b][0];
                            const UInt32 raw_right = opts->sack[b][1];
                            if (SeqLt(raw_left, ack_base) && SeqLt(raw_right, ack_base)) {
                                continue;  // wholly behind the cumulative ACK
                            }
                            UInt64 left = rot(raw_left);
                            UInt64 right = rot(raw_right);
                            if (left > right) {
                                left = static_cast<UInt64>(ack_base);  // wrapped block
                            }
                            if (cursor < left) {
                                gaps_remain = true;
                                break;
                            }
                            cursor = right;
                        }
                        if (SeqLt(static_cast<UInt32>(cursor), snd_nxt_)) {
                            gaps_remain = true;
                        }
                    } else {
                        // Kernel tcp_fastretrans_alert part D (tcp_input_66.c:
                        // 2995-3001): the state-exit test is ONLY
                        //
                        //     } else if (!before(tp->snd_una, tp->high_seq)) {
                        //
                        // i.e. the episode ends when the cumulative ACK
                        // reaches high_seq, and NOT on a partial ACK. A
                        // partial ACK (snd_una < high_seq) therefore stays in
                        // CA_Recovery and falls through to part E, where the
                        // NewReno arm (tcp_identify_packet_loss ->
                        // tcp_newreno_mark_lost) marks and retransmits the
                        // next hole (RFC 6582 s3.2).
                        //
                        // The port computed gaps_remain only from SACK blocks,
                        // so a no-SACK partial ACK looked like "no gaps" and
                        // took the exit branch - closing the recovery on the
                        // first partial ACK and stranding the rest of the
                        // burst behind the RTO (audit D18).
                        gaps_remain = SeqLt(ack, high_seq_);
                    }
                    if (!gaps_remain) {
                        // Kernel tcp_is_non_sack_preventing_reopen
                        // (tcp_input.c:2535-2548) / tcp_try_undo_recovery
                        // (tcp_input.c:2551-2577): the undo runs FIRST, and
                        // only then does a NON-SACK recovery at exactly
                        // high_seq stay open (reopening there lets the very
                        // next dup-ACK start a false fast retransmit,
                        // RFC 2582). tcp_fastretrans_alert then returns out of
                        // part D (tcp_input.c:3015-3016), so the episode is NOT
                        // closed on this ACK and no COMPLETE_CWR fires.
                        //
                        // tcp_cong_control still runs afterwards
                        // (tcp_input.c:3939) and, because the state is still
                        // Recovery, takes tcp_cwnd_reduction (tcp_input.c:3523)
                        // - i.e. PRR keeps running on this very ACK.
                        const bool hold_reno =
                            (snd_una_ == high_seq_) && !sack_ok_;
                        if (hold_reno) {
                            // tcp_is_non_sack_preventing_reopen keeps the
                            // state, fast_recovery_, high_seq_ and the
                            // reduction bookkeeping. Part D above already ran
                            // the undo (tcp_try_undo_recovery) and left the
                            // candidate alone when there was nothing to undo -
                            // a later DSACK may still undo (the kernel does not
                            // clear undo_marker on this path either).
                        } else {
                            // Linux tcp_try_undo_recovery: tcp_may_undo()
                            // decides between "restore the pre-cut window" and
                            // "the reduction stands at ssthresh".
                            if (TcpMayUndo(opts)) {
                                if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->undo_cwnd &&
                                    0 != prior_cwnd_) {
                                    cc_.snd_cwnd = cc_ops_->undo_cwnd(&cc_);
                                } else {
                                    cc_.snd_cwnd = prior_cwnd_;
                                }
                                if (prior_ssthresh_ > cc_.snd_ssthresh) {
                                    cc_.snd_ssthresh = prior_ssthresh_;
                                }
                                undo_marker_ = false;
                                episode_undone_ = true;  // kernel tcp_undo_cwnd_reduction
                            }
                            fast_recovery_ = false;
                            sack_retx_next_ = 0;
                            undo_retrans_ = -1;
                            // The recovery ends here: the CA state must follow
                            // (kernel tcp_try_undo_recovery -> tcp_set_ca_state
                            // (TCP_CA_Open) at tcp_input.c:2574), and only
                            // then does tcp_end_cwnd_reduction run (:3017) -
                            // so the COMPLETE_CWR event observes CA_Open.
                            SetCaState(0);
                            EndCwndReduction();
                            high_seq_ = 0;
                            // No RTO verdict can outlive its episode.
                            rto_pending_ = false;
                            rto_retx_end_ = 0;
                            retrans_stamp_ts_ = 0;
                        }
                    } else {
                        // Real gaps remain: the partial ACK does not close the
                        // episode, but it does NOT invalidate the undo
                        // candidate either. The kernel's tcp_try_undo_partial
                        // leaves tp->undo_marker alone on the no-undo path -
                        // only a SUCCESSFUL undo (tcp_try_undo_recovery,
                        // :2526), ECN (tcp_enter_cwr, :2692), a simple
                        // retransmit (:2812) or tcp_clear_retrans (:2101)
                        // clears it. A D-SACK arriving later in this same
                        // episode must still be able to prove the
                        // retransmission spurious (audit D17).
                        // RFC 6675: a partial ACK (with SACK-implied gaps
                        // remaining) itself drives the recovery - retransmit
                        // the next missing segment immediately instead of
                        // waiting for a fresh duplicate ACK.
                        // Do not rewind the walk: dupack-driven retransmits may
                        // already have advanced sack_retx_next_ past the ACK.
                        if (SeqLt(sack_retx_next_, ack)) {
                            sack_retx_next_ = ack;
                        }
                        // A partial ACK without SACK blocks marks the new queue
                        // head lost and retransmits it (NewReno, audit D18),
                        // while STILL deflating cwnd to ssthresh on this ACK:
                        //
                        // [retained deviation] The deflation has no direct
                        // kernel counterpart: the kernel leaves cwnd to
                        // tcp_cwnd_reduction (PRR) for the whole recovery. The
                        // port keeps it because the Reno no-SACK path has no
                        // SACK scoreboard to drive PRR's delivered/out balance;
                        // removing it re-introduces the per-ACK retransmit
                        // storm. Only the classic (non-plugin) path reaches
                        // here - a plugin CC with cong_control never enters
                        // this block (guard above).
                        if (NULLPTR == opts || 0 == opts->sack_count) {
                            // Kernel tcp_identify_packet_loss (tcp_input_66.c:
                            // 2941-2956) dispatches the NewReno arm for a
                            // non-SACK connection:
                            //
                            //     if (unlikely(tcp_is_reno(tp)))
                            //         tcp_newreno_mark_lost(sk,
                            //             *ack_flag & FLAG_SND_UNA_ADVANCED);
                            //
                            // tcp_newreno_mark_lost (tcp_recovery_66.c:217-236)
                            // marks the retransmit-queue HEAD lost when
                            //   (state < Recovery && sacked_out >= reordering) ||
                            //   (state == Recovery && snd_una_advanced)
                            // and tcp_xmit_recovery retransmits it. That IS
                            // NewReno (RFC 6582 s3.2): every partial ACK
                            // repairs one hole, so recovery advances one
                            // segment per round trip. The port only deflated
                            // cwnd here, so the hole waited for the RTO
                            // (audit D18).
                            cc_.snd_cwnd = cc_.snd_ssthresh;
                            if (!retrans_queue_.empty()) {
                                SentSeg& head = retrans_queue_.front();
                                if (head.sacked < head.len && 0 == head.lost) {
                                    head.lost = 1;
                                    lost_out_pkts_ += head.pkt_count;
                                    PipeReaccountSeg(head, head.sacked, 0, head.is_retrans);
                                }
                            }
                            RetransmitFront(now);
                        } else {
                            RetransmitEarliestMissing(now, opts);
                        }
                    }
                }
                // Kernel tcp_identify_packet_loss (tcp_input_66.c:2941-2956)
                // runs from tcp_fastretrans_alert part E, i.e. OUTSIDE the
                // cong_control early-return that guards tcp_cong_control
                // (:3513-3531). It is LOSS DETECTION, not window management,
                // so it applies to every CC:
                //
                //     if (unlikely(tcp_is_reno(tp)))
                //         tcp_newreno_mark_lost(sk,
                //             *ack_flag & FLAG_SND_UNA_ADVANCED);
                //
                // tcp_newreno_mark_lost (tcp_recovery_66.c:217-236) marks the
                // retransmit-queue HEAD lost when the state is Recovery and
                // snd_una advanced; tcp_xmit_recovery then retransmits it.
                // That is NewReno (RFC 6582 s3.2): each partial ACK repairs
                // one hole, so recovery advances one segment per round trip.
                //
                // The port had this inside the cong_control-guarded PRR block,
                // so a no-SACK recovery driven by a plugin CC never marked or
                // retransmitted the next hole - it waited for the RTO (audit
                // D18). A plugin without an ssthresh hook takes the classic
                // path above and is already covered there.
                if (fast_recovery_ && !sack_ok_ && NULLPTR != cc_ops_ &&
                    NULLPTR != cc_ops_->cong_control) {
                    if (!retrans_queue_.empty()) {
                        SentSeg& head = retrans_queue_.front();
                        if (head.sacked < head.len && 0 == head.lost) {
                            head.lost = 1;
                            lost_out_pkts_ += head.pkt_count;
                            PipeReaccountSeg(head, head.sacked, 0, head.is_retrans);
                        }
                    }
                    RetransmitFront(now);
                }
                // Kernel send order (tcp_input.c:3938-3940):
                //   tcp_rate_gen -> tcp_cong_control -> tcp_xmit_recovery
                // i.e. the CC has already had its say about cwnd when new data
                // leaves. The flush therefore runs AFTER the CC hook and after
                // the PRR block above - never before them. (Before dfe0b55 the
                // exit block did not raise cwnd, so the old position was
                // harmless; with the exit block in place it released the whole
                // backlog at 0x7FFFFFFF - audit D01.)
                if (0 < pending_send_.size()) {
                    FlushPendingSend(now);  // buffered sends ride the freed window
                }
            } else {
                // Duplicate ACK on the frontier (ack == snd_una_). It may still carry a window
                // update (the peer re-advertised after our persist probe):
                // flush buffered sends against the freshly advertised window.
                // B2: once the window is non-zero, probing must stop here too
                // (mirror of the stale-ACK and cumulative-ACK paths) -
                // otherwise persist keeps firing against an open window.
                if (0 < snd_wnd_) {
                    persist_deadline_ = 0;
                    persist_interval_ = persist_base_;  // restore user-configured base
                }
                if (0 < pending_send_.size()) {
                    FlushPendingSend(now);
                }
                // Duplicate ACK on the frontier. Data-bearing segments
                // (ack_not_dup_) keep the ACK processing below but
                // are not counted toward the dupthresh.
                if (!ack_not_dup_) {
                    ++dup_acks_;
                }
                // RFC 8985 RACK: the time-based verdict can fire BEFORE the
                // 3-dup threshold - once the reorder window has elapsed, a
                // gap behind the RACK anchor is loss, not order. Runs on
                // every dup-ACK (the SACK blocks refreshed the anchor).
                RackDetectLoss(now);
                // RFC 5827 Early Retransmit (no-SACK path): a small flight
                // (2-3 segments) can produce AT MOST oseg-1 duplicate ACKs
                // (the first in-order arrival consumes one cumulative ACK),
                // so the RFC 5681 threshold of 3 is physically unreachable
                // and the loss waits for the 1s RTO. When the window is
                // small AND limited transmit cannot inject new data (no
                // pending bytes, or the peer window / our cwnd is exhausted),
                // lower the threshold to min(3, oseg-1): the LAST possible
                // dup triggers the fast retransmit. SACK connections are
                // covered by RACK (sack_ok_ gate at RackDetectLoss), so ER
                // applies only to !sack_ok_ - the two never overlap.
                UInt32 dupthresh = 3;
                if (!sack_ok_ && !fast_recovery_ && !retrans_queue_.empty()) {
                    const UInt32 oseg = static_cast<UInt32>(retrans_queue_.size());
                    if (2 <= oseg && oseg < 4) {
                        const UInt32 inflight = snd_nxt_ - snd_una_;
                        const bool no_inject = pending_send_.empty() ||
                            snd_wnd_ <= inflight ||
                            cc_.snd_cwnd * peer_mss_ <= inflight;
                        if (no_inject) {
                            dupthresh = oseg - 1;  // {1,2}: the last possible dup fires
                        }
                    }
                }
                if (!fast_recovery_ && dupthresh <= dup_acks_ && !retrans_queue_.empty()) {
                    // Reordering gate: the
                    // Linux peer's dup-ACKs on a lossless link carried SACK
                    // blocks that added NO new information (ranges at/below
                    // the cum-ACK) while the front was merely in flight -
                    // 3 such dups collapsed cwnd (ssthresh=2) and
                    // retransmitted ~30 live segments per 1MB echo. The gate
                    // blocks ONLY that shape: SACK-carrying dup-ACKs with no
                    // real gap behind the front, while the front is recent
                    // (< 3 RTT, 1ms floor). No-SACK dups keep RFC 5681
                    // semantics (fast-retransmit on 3 dups); a SACK block
                    // revealing a REAL gap is a confirmed loss (retransmit
                    // regardless of age).
                    bool sack_no_gap = (NULLPTR != opts && 0 < opts->sack_count);
                    if (sack_no_gap) {
                        UInt64 cursor = static_cast<UInt64>(snd_una_);
                        for (Byte b = 0; b < opts->sack_count; ++b) {
                            const UInt32 raw_left = opts->sack[b][0];
                            const UInt32 raw_right = opts->sack[b][1];
                            if (SeqLt(raw_right, snd_una_)) {
                                continue;  // wholly behind the frontier
                            }
                            const UInt64 left = SeqLt(raw_left, snd_una_)
                                ? static_cast<UInt64>(snd_una_) : static_cast<UInt64>(raw_left);
                            const UInt64 right = SeqLt(raw_right, snd_una_)
                                ? static_cast<UInt64>(snd_una_) : static_cast<UInt64>(raw_right);
                            if (cursor < left) {
                                sack_no_gap = false;  // real gap: confirmed loss
                                break;
                            }
                            cursor = right;
                        }
                        if (!SeqLt(static_cast<UInt32>(cursor), snd_nxt_)) {
                            sack_no_gap = false;  // covers everything: no gap
                        }
                    }
                    const bool front_recent = (0 < now) &&
                        (now < retrans_queue_.front().sent_at +
                            static_cast<TimePoint>(3ull * srtt_ > 1000 ? 3ull * srtt_ : 1000));
                    if (sack_no_gap && front_recent) {
                        // SACK-carrying dup-ACKs, no real gap, recent front:
                        // reordering / zero-info, not loss. Do not cut cwnd or
                        // retransmit; drop the dup-ACK count so the next send
                        // + ACK cycle starts fresh.
                        dup_acks_ = 0;
                    } else {
                    // RFC 5681 fast retransmit: cut, inflate, retransmit.
                    // RFC 6675: SACK-aware recovery starts at the front gap.
                    // Linux tcp_try_undo_recovery: a fast-recovery entry driven
                    // by duplicate ACKs WITHOUT SACK blocks carries no
                    // confirmed-loss signal (the peer may simply have reordered
                    // or the ACKs may be spurious) - save the pre-cut window so
                    // a clean recovery exit can undo it. SACK-driven entries
                    // (real gaps) never undo.
                    prior_cwnd_ = cc_.snd_cwnd;
                    prior_ssthresh_ = cc_.snd_ssthresh;
                    // Kernel tcp_enter_recovery (tcp_input_66.c:2816-2839)
                    // calls tcp_init_undo UNCONDITIONALLY (:2826):
                    //
                    //     tp->undo_marker  = tp->snd_una;
                    //     tp->undo_retrans = tp->retrans_out ?: -1;
                    //
                    // There is no SACK/no-SACK distinction: a SACK-driven
                    // recovery is just as undoable as a dup-ACK one, because
                    // the actual undo still needs EVIDENCE - a D-SACK covering
                    // the retransmission (tcp_try_undo_dsack, :2580) or
                    // tcp_packet_delayed. The port used to arm the candidate
                    // only for SACK-less entries, so a spurious retransmission
                    // confirmed by a D-SACK inside a SACK-driven episode could
                    // never be undone (audit D17).
                    undo_marker_ = true;
                    undo_retrans_ = (retrans_out_pkts_ > 0)
                        ? static_cast<Int32>(retrans_out_pkts_) : -1;
                    // Kernel dup-ACK loss marking (tcp_mark_head_lost): the
                    // head of the retransmission queue becomes TCPCB_LOST at
                    // the fast-retransmit decision.
                    if (!retrans_queue_.empty()) {
                        SentSeg& head = retrans_queue_.front();
                        if (head.sacked < head.len && 0 == head.lost) {
                            head.lost = 1;
                            lost_out_pkts_ += head.pkt_count;
                            // LOST takes the segment out of the pipe.
                            PipeReaccountSeg(head, head.sacked, 0, head.is_retrans);
                        }
                    }
                    CutCwnd();
                    // RFC 6937 PRR (proportional rate reduction): during the
                    // recovery the cwnd is driven by the delivered/out
                    // balance instead of a fixed ssthresh+3 inflation, so the
                    // send rate stays proportional to the recovery progress
                    // (fast recoveries complete fast, slow ones stay bounded).
                    // RecoverFS anchors the delivered/out accounting. PACKETS
                    // (kernel tp->recover_fs = tcp_packets_in_flight).
                    recover_fs_ = PktCount(snd_nxt_ - snd_una_, peer_mss_);
                    prr_delivered_ = 0;
                    prr_out_ = 0;
                    // RFC 5681 ssthresh+3 inflation is CLASSIC RENO ONLY.
                    // A plugin with an ssthresh hook owns its own reduction:
                    // the kernel enters recovery through tcp_init_cwnd_reduction
                    // -> tcp_cwnd_reduction (cwnd = packets_in_flight + sndcnt),
                    // never through ssthresh+3. Applying it here would also
                    // overflow: KCC's hook passes the current ssthresh through
                    // (0x7FFFFFFF), so ssthresh+3 = 0x80000002 - not a legal
                    // window (and above the kernel's snd_cwnd_clamp).
                    if (NULLPTR == cc_ops_ || NULLPTR == cc_ops_->ssthresh) {
                        cc_.snd_cwnd = cc_.snd_ssthresh + 3;
                    }
                    SetCaState(3);   // kernel CA_Recovery
                    // Kernel tcp_init_cwnd_reduction: tp->high_seq = tp->snd_nxt.
                    high_seq_ = snd_nxt_;
                    fast_recovery_ = true;
                    fast_retransmit_seq_ = retrans_queue_.front().seq;
                    sack_retx_next_ = snd_una_;
                    last_retx_seq_ = 0;  // storm gate: allow the entry retransmit
                    last_retx_len_ = 0;
                    dup_acks_ = 0;
                    if (dupthresh < 3) {
                        ++er_losses_;  // RFC 5827 ER entry (diagnostic, rack_losses_ style)
                    }
                    RetransmitEarliestMissing(now, opts);
                    }
                } else if (fast_recovery_) {
                    // RFC 6675 SACK recovery: use each dupack to retransmit
                    // the next earliest missing segment (SACK-implied gaps).
                    // RFC 5681's "+1 per dupack" cwnd inflation exists for
                    // classic Reno WITHOUT SACK; with SACK it is omitted so
                    // the send window stays at ssthresh+3 during recovery -
                    // otherwise the inflation grows unbounded (one per
                    // dupack) and the resulting send burst floods a small
                    // bottleneck buffer, silently dropping the retransmits.
                    if (NULLPTR == opts || 0 == opts->sack_count) {
                        // Classic Reno (no SACK): the retransmit happened on
                        // entry; a duplicate ACK only inflates cwnd (RFC
                        // 5681). Re-transmitting the front on EVERY dupack is
                        // a retransmit storm: the peer (which already has the
                        // data) answers each duplicate with another dupack
                        // (observed: 55k retransmits for a 1MB echo against
                        // a real kernel, rto_retx=0). Only true duplicate
                        // ACKs inflate (Linux gates tcp_add_reno_sack on
                        // !FLAG_NOT_DUP).
                        if (!ack_not_dup_) {
                            cc_.snd_cwnd += 1;
                        }
                    } else {
                        // SACK blocks during the recovery: they narrow the
                        // loss set but do NOT invalidate the undo candidate.
                        // The kernel clears tp->undo_marker only in
                        // tcp_clear_retrans (:2101), tcp_try_undo_recovery on
                        // success (:2526), tcp_enter_cwr for ECN (:2692),
                        // tcp_simple_retransmit (:2812) and the SYN-timeout
                        // path (:6214) - never because an ordinary SACK block
                        // arrived. Clearing it here made every D-SACK-confirmed
                        // spurious retransmission inside a SACK recovery
                        // impossible to undo (audit D17).
                        // Zero-info guard: SACK blocks at/below the cum-ACK add NO new
                        // information (the Linux peer re-ACKs already-ACKed
                        // data on a lossless link). RetransmitEarliestMissing
                        // would walk the queue one segment per such dup
                        // (the storm gate advances sack_retx_next_ on every
                        // blocked re-send) - observed 20 over-retransmissions
                        // for 20 zero-info dups during recovery. Only walk
                        // when the SACKs reveal a gap BEYOND the front.
                        bool sack_zero_info = true;
                        {
                            UInt64 cursor = static_cast<UInt64>(snd_una_);
                            for (Byte b = 0; b < opts->sack_count; ++b) {
                                const UInt32 raw_left = opts->sack[b][0];
                                const UInt32 raw_right = opts->sack[b][1];
                                if (SeqLt(raw_right, snd_una_)) {
                                    continue;  // wholly behind the frontier
                                }
                                const UInt64 left = SeqLt(raw_left, snd_una_)
                                    ? static_cast<UInt64>(snd_una_) : static_cast<UInt64>(raw_left);
                                const UInt64 right = SeqLt(raw_right, snd_una_)
                                    ? static_cast<UInt64>(snd_una_) : static_cast<UInt64>(raw_right);
                                if (cursor < left) {
                                    sack_zero_info = false;  // real gap: walk
                                    break;
                                }
                                cursor = right;
                            }
                        }
                        if (!sack_zero_info) {
                            RetransmitEarliestMissing(now, opts);
                        }
                    }
                    dup_acks_ = 0;
                }

                // Kernel tcp_rate_gen runs on EVERY ACK (tcp_input.c:3939),
                // including a duplicate ACK whose only progress is
                // SACK/DSACK delivery (sack_state.sack_delivered is folded
                // into tp->delivered at tcp_input.c:3879-3881). Without
                // this, a DSACK-only dup-ACK produced no rate sample at all:
                // the delivered packet was counted in cc_.delivered_pkts but
                // never reported to the CC hook.
                if (cc_.delivered_pkts > delivered_pkts_at_entry ||
                    cc_.delivered > delivered_bytes_at_entry) {
                    EmitRateSample(now, 0, 0, prior_in_flight_bytes, ack);
                }
            }
        }

        void TcpConn::PipeAccountSeg(const SentSeg& seg, int sign) noexcept {
            PipeAccountFields(seg.len, seg.sacked, seg.lost, seg.is_retrans, sign);
        }

        void TcpConn::PipeAccountFields(UInt32 len, UInt32 sacked, Byte lost,
                                        Byte is_retrans, int sign) noexcept {
            // One segment's contribution to the three terms PipeInFlightBytes
            // used to recompute by walking the whole queue. Takes plain values
            // so callers can describe a PREVIOUS state of the segment without
            // copying it (SentSeg owns a BufRef and is not copyable).
            //
            // The retransmission term is keyed on is_retrans (kernel
            // TCPCB_SACKED_RETRANS), NOT on retries>0: the kernel's retrans_out
            // is its own counter driven by that flag, and the TFO path marks
            // early data as retransmitted without bumping `retries` (it was
            // first sent in the SYN, so it is not a retry).
            const UInt32 unsacked = (sacked < len) ? (len - sacked) : 0;
            const UInt32 lost_bytes = (0 != lost) ? unsacked : 0;
            const UInt32 retrans_bytes = (0 != is_retrans) ? unsacked : 0;
            if (sign > 0) {
                pipe_sacked_bytes_ += sacked;
                pipe_lost_bytes_ += lost_bytes;
                pipe_retrans_bytes_ += retrans_bytes;
            } else {
                pipe_sacked_bytes_ = (pipe_sacked_bytes_ >= sacked)
                    ? pipe_sacked_bytes_ - sacked : 0;
                pipe_lost_bytes_ = (pipe_lost_bytes_ >= lost_bytes)
                    ? pipe_lost_bytes_ - lost_bytes : 0;
                pipe_retrans_bytes_ = (pipe_retrans_bytes_ >= retrans_bytes)
                    ? pipe_retrans_bytes_ - retrans_bytes : 0;
            }
        }

        void TcpConn::PipeReaccountSeg(const SentSeg& seg, UInt32 old_sacked,
                                       Byte old_lost, Byte old_is_retrans) noexcept {
            // Remove the old contribution, add the new one. Only the three
            // mutable fields participate, so this stays O(1).
            PipeAccountFields(seg.len, old_sacked, old_lost, old_is_retrans, -1);
            PipeAccountFields(seg.len, seg.sacked, seg.lost, seg.is_retrans, +1);
        }

        UInt32 TcpConn::PipeInFlightBytes() const noexcept {
            // Kernel tcp_packets_in_flight():
            //   packets_out - tcp_left_out(tp) + retrans_out
            //   tcp_left_out = sacked_out + lost_out   (tcp_h_v66.h:1198-1220)
            // SACKed bytes sit in the receiver's buffer and LOST bytes have
            // been declared gone from the network - neither occupies the
            // pipe, so both are subtracted. Retransmitted bytes are back in
            // flight (retrans_out) and are added again.
            //
            // O(1): the three sums are maintained incrementally at every
            // queue/segment mutation (PipeAccountSeg / PipeReaccountSeg). The
            // kernel derives the same value from its O(1) counters; walking the
            // queue here cost ~850 iterations per ACK at a 100 Gbps BDP.
            const UInt32 inflight = snd_nxt_ - snd_una_;
            const UInt32 left_out = pipe_sacked_bytes_ + pipe_lost_bytes_;
            const UInt32 base = (inflight > left_out) ? (inflight - left_out) : 0;
            return base + pipe_retrans_bytes_;
        }

        UInt32 TcpConn::PipeBytes() const noexcept {
            // RFC 6675 pipe = (HighData - HighACK) - SACKed + Retransmitted.
            // SACKed bytes sit in the receiver's buffer (not the network) and
            // retransmitted-but-unacked bytes occupy the pipe twice, so the
            // pipe is the true in-network occupancy - the cwnd (inflated to
            // ssthresh+3 during recovery) overcounts it and stalls new data.
            //
            // O(1) via the same incremental sums PipeInFlightBytes uses. The
            // only difference between the two is LOST: RFC 6675's pipe keeps
            // counting lost-but-unretransmitted bytes, tcp_packets_in_flight
            // does not.
            const UInt32 inflight = snd_nxt_ - snd_una_;
            return (inflight > pipe_sacked_bytes_)
                ? (inflight - pipe_sacked_bytes_ + pipe_retrans_bytes_)
                : pipe_retrans_bytes_;
        }

        bool TcpConn::SendData(const Byte* data, UInt32 len, TimePoint now) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            if (0 == len) {
                return true;
            }
            // Full client semantics: data sent right after Connect() is queued
            // while the SYN/SYN+ACK handshake is in flight and flushed once
            // the connection reaches Established.
            if (TcpState::kSynSent == state_ || TcpState::kSynRcvd == state_) {
                if (snd_buf_ < pending_send_.size() + len) {
                    return false;  // queue full: caller backs off
                }
                pending_send_.insert(pending_send_.end(), data, data + len);
                timers_dirty_.store(true, std::memory_order_relaxed);
                return true;
            }
            // RFC 793 half-close: in CloseWait (the peer sent FIN and closed
            // its send side) the application may still send data. Established
            // is the normal send state.
            if (TcpState::kEstablished != state_ && TcpState::kCloseWait != state_) {
                return false;
            }
            const UInt32 inflight = snd_nxt_ - snd_una_;
            // Kernel tcp_rate_check_app_limited runs at the sendmsg entry,
            // BEFORE the new data is consumed: an idle burst's first segment
            // must carry the marker so the CC can detect the idle restart.
            // `now` is the SendData entry timestamp: re-reading the clock
            // here cost one extra vDSO call per application send on the
            // pacing path (profile: clock_gettime was the top self item).
            MaybeMarkAppLimited(inflight, now);
            // Segment at the source: one application send may exceed the MSS,
            // but the wire packet must not (DF + MSS negotiation). Buffered
            // bytes are flushed in MSS-sized segments below, so the tx
            // boundary (software GSO) never has to re-segment hot-path data.
            // TCP-MD5 additionally caps at MSS-20 (the option is 20 header
            // bytes and must never be rebuilt by segmentation).
            const UInt32 payload_cap = Md5Enabled() ? ((peer_mss_ > 20) ? (peer_mss_ - 20) : 0)
                                                    : peer_mss_;
            // Send window = min(congestion window, peer window, local quota).
            const UInt64 cwnd_bytes = static_cast<UInt64>(cc_.snd_cwnd) * peer_mss_;
            if (len > payload_cap) {
                if (snd_buf_ < pending_send_.size() + len + inflight) {
                    return false;
                }
                // TSO direct-send (backends with kCapTsoTx): hand the whole
                // super-segment to the NIC in ONE Tx instead of buffering
                // and flushing MSS-sized segments. The gates keep recovery
                // and ordering clean: no outstanding segments (an oversized
                // entry must never enter an active recovery), no buffered
                // bytes ahead of it, a clean send window, cwnd and pacing
                // clock, and the pool must hold the super-segment (its max
                // class is 32KB; anything bigger falls back to buffering).
                // The Emit-side TSO gate re-validates the caps and qdisc.
                const bool tso_direct = tso_tx_ && pending_send_.empty() &&
                    retrans_queue_.empty() && !fast_recovery_ &&
                    inflight + len <= snd_wnd_ &&
                    inflight + len <= cwnd_bytes &&
                    (0 == cc_.pacing_rate || now >= pacing_deadline_) &&
                    len + 40 <= xtcp::buf::kMaxPoolPayload;
                if (!tso_direct) {
                    // Super-MSS sends are buffered and flushed in MSS-sized
                    // segments by FlushPendingSend (the direct-send variant
                    // was reverted: it could overrun the window and corrupt
                    // recovery under loss - see discover.md).
                    pending_send_.insert(pending_send_.end(), data, data + len);
                    timers_dirty_.store(true, std::memory_order_relaxed);
                    // RFC 1122 zero-window probing applies to super-MSS buffers
                    // too: while the peer advertises zero, arm probes so a lost
                    // window-update ACK cannot deadlock the flow.
                    if (0 == snd_wnd_ && (0 == persist_deadline_ || now < persist_deadline_)) {
                        persist_deadline_ = now + persist_interval_;
                    }
                    return true;
                }
                // TSO direct: fall through to the direct-send path with the
                // whole payload (the window/cwnd bounds were verified above
                // and are re-verified by the shared checks below).
            }
            // Send window = min(congestion window, peer window, local quota).
            // The snd_buf_ quota keeps the retransmission queue (hence the
            // connection's memory) mathematically bounded; the cwnd keeps
            // the flow fair on a shared bottleneck (RFC 5681).
            UInt32 limit = snd_buf_;
            if (cwnd_bytes < limit) {
                limit = static_cast<UInt32>(cwnd_bytes);
            }
            if (snd_wnd_ < limit) {
                limit = snd_wnd_;
            }
            // RFC 6675 pipe estimate: during fast recovery the pipe (bytes
            // actually in the network - SACKed data excluded, retransmitted
            // data counted) replaces the cwnd for gating NEW data. SACKed
            // bytes sit in the receiver's buffer, so the cwnd (inflated to
            // ssthresh+3) overcounts the pipe and stalls the recovery tail.
            // Linux tcp_pipe semantics: send new data while pipe + len <=
            // ssthresh; the cwnd cap is dropped during recovery (RFC 6675
            // 4.2: "the congestion window is not used to limit sending").
            bool pipe_gated = false;
            if (fast_recovery_) {
                const UInt64 ssthresh_bytes = static_cast<UInt64>(cc_.snd_ssthresh) * peer_mss_;
                pipe_gated = (static_cast<UInt64>(PipeBytes()) + len > ssthresh_bytes);
                limit = (snd_wnd_ < snd_buf_) ? snd_wnd_ : snd_buf_;
            }
            // Full Linux send semantics: when the window or the pacing clock
            // forbids an immediate send, buffer instead of failing, so apps
            // that do fire-and-forget sends (echo servers) never drop data.
            // The buffered bytes ride the freed window (OnAckReceived flush).
            // RFC 896 Nagle (Minshall variant): with nodelay off, a small
            // segment waits only while at least one full MSS is already in
            // flight - gating on any nonzero inflight strands small sends
            // behind a 1-byte persist probe or a drained pipe (RFC 1122
            // 4.2.3.4: transmit immediately when inflight < MSS).
            const bool nagle = (!nodelay_ && len < peer_mss_ && inflight >= peer_mss_);
            if (!pending_send_.empty() || inflight + len > limit || pipe_gated || nagle ||
                (0 < cc_.pacing_rate && now < pacing_deadline_)) {
                if (snd_buf_ < pending_send_.size() + len + inflight) {
                    return false;  // app must back off (buffered sends)
                }
                pending_send_.insert(pending_send_.end(), data, data + len);
                timers_dirty_.store(true, std::memory_order_relaxed);
                // RFC 1122 zero-window probing: while the peer advertises a
                // zero window, schedule probes so a lost window-update ACK
                // cannot deadlock the flow.
                if (0 == snd_wnd_ && (0 == persist_deadline_ || now < persist_deadline_)) {
                    persist_deadline_ = now + persist_interval_;
            timers_dirty_.store(true, std::memory_order_relaxed);
                }
                return true;
            }
            // Hard memory bound: the direct-send path must also count the
            // buffered bytes (pending + inflight + this send <= snd_buf_),
            // otherwise buffering bypasses the per-connection quota.
            if (snd_buf_ < pending_send_.size() + len + inflight) {
                return false;
            }
            const UInt32 seq = snd_nxt_;
            buf::BufRef packet;
            {
                buf::TxAcquireScope tx_class(&tx_waiter_);
                packet = BuildSegmentPacket(local_, remote_, seq, rcv_nxt_,
                                                    kFlagAck | kFlagPsh |
                                                        (cwr_pending_ ? kFlagCwr : 0), data, len,
                                                    AdvertisedWindow(), rcv_wscale_,
                                                    Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
            }
            if (packet.IsEmpty()) {
                // Pool exhaustion on the direct-send path: buffer instead of
                // failing, so apps that do fire-and-forget sends never drop
                // data (mirror of the buffered branch above). The snd_buf_
                // quota was already checked (pending + inflight + len <=
                // snd_buf_, line above) and pending is empty on this path, so
                // the insert stays within budget. FlushPendingSend drains the
                // buffer as the window frees and re-queues on repeated
                // exhaustion (FlushPendingSend packet.IsEmpty()). cwr_pending_
                // stays set so the flush still emits the CWR.
                MarkPoolLimited(inflight);
                pending_send_.insert(pending_send_.end(), data, data + len);
                timers_dirty_.store(true, std::memory_order_relaxed);
                return true;
            }
            tx_waiter_.Cancel();
            cwr_pending_ = false;  // CWR emitted on this data segment (RFC 3168 s6.1.2)
            // Kernel CA_EVENT_TX_START gate: tcp_packets_in_flight == 0
            // (tcp_output_v66.c:167-168), evaluated at the emit point.
            const bool pipe_empty = (0 == PipeInFlightBytes());
            snd_nxt_ += len;
            // RFC 6937 PRR: packets sent during the recovery count against the
            // proportional cwnd (delivered - out balance). PACKET domain: the
            // kernel's prr_out is incremented by tcp_skb_pcount, not by bytes.
            if (fast_recovery_) {
                prr_out_ += PktCount(len, peer_mss_);
            }
            SentSeg seg;
            seg.seq = seq;
            seg.len = len;
            seg.sent_at = now;
            seg.rto = 0;
            seg.sent_delivered = cc_.delivered;
            seg.sent_delivered_pkts = cc_.delivered_pkts;
            seg.pkt_count = PktCount(len, peer_mss_);
            seg.app_limited = (0 != cc_.app_limited) ? 1 : 0;
            seg.data = std::move(packet);  // retain for zero-copy retransmit
            // Kernel CA_EVENT_TX_START: the first data segment on an idle
            // pipe (no retransmissions: intentionally narrowed to new data).
            NotifyTxStart(pipe_empty);

            // Reentrancy-safe order (D12): the segment MUST enter the
            // retransmission queue BEFORE the sink emits it. Synchronous
            // backends (loopback peers, in-memory injects) deliver the
            // peer's ACK reentrantly INSIDE sink_(); a queue that is still
            // missing this segment processes that ACK against the old
            // snd_una_, advancing past it - and the segment, pushed
            // afterwards, is never reaped (its ACK already came). The RTO
            // then retransmits ACKed data and the stream stalls (test_tso_tx
            // WSL regression). With the push first, a reentrant ACK sees the
            // complete queue and drains the segment normally.
            // Account BEFORE the move: push_back moves `seg` out.
            PipeAccountSeg(seg, +1);
            retrans_queue_.push_back(std::move(seg));
            if (1 == retrans_queue_.size()) {
                ArmRetransmit(now);
                // TCP_USER_TIMEOUT anchor: the send time of the OLDEST
                // unacked segment. A separate anchor (not the front's
                // sent_at, which the Karn guard clears to 0 on retransmit)
                // so a retransmission cannot reset the user-timeout clock -
                // the data has been outstanding since its first send.
                first_outstanding_ = now;
            }
            // RFC 8985 TLP: arm the tail-loss probe after the segment is in
            // the queue (the arming must see the just-pushed segment, or a
            // single-segment send - whose tail IS this segment - never
            // arms). The probe fires after ~2xRTT (well before the RTO),
            // retransmitting the tail - avoiding the RTO's window cut and
            // latency penalty for a single lost tail segment.
            if (!fast_recovery_ && 0 < srtt_ && 0 == pending_send_.size()) {
                TimePoint tlp = now + static_cast<TimePoint>(2ull * srtt_);
                if (tlp < now + 10000) {
                    tlp = now + 10000;  // 10ms floor
                }
                if (!tlp_armed_ || tlp < tlp_deadline_) {
                    tlp_deadline_ = tlp;
                }
                tlp_armed_ = true;
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
            if (sink_) {
                sink_(retrans_queue_.back().data.Clone());
            }
            // Kernel tcp_packets_in_flight(tp) = packets_out - (sacked_out + lost_out)
                // + retrans_out (tcp_h_66.h:1198-1220). The raw snd_nxt-snd_una
                // distance counts SACKed and LOST bytes as in flight, so every
                // CC consumer (tcp_cwnd_reduction's cwnd = inflight + sndcnt,
                // KCC packet_conservation, BBR's bdp gate) saw an inflated
                // pipe during recovery (audit B5-D3 / B6-D1).
                cc_.inflight = PipeInFlightBytes();
            cc_.lsndtime = now / 1000;
            // Pace: schedule the next send len/rate microseconds later.
            if (0 < cc_.pacing_rate) {
                pacing_deadline_ = now + (static_cast<UInt64>(len) * 1000000ull) / cc_.pacing_rate;
            }
            return true;
        }

        void TcpConn::OnPersistTimer(TimePoint now) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            if (0 == persist_deadline_ || now < persist_deadline_) {
                return;
            }
            // RFC 1122 s4.2.2.17: persist while the peer's window is zero.
            // The probe is a 1-byte segment so the peer re-advertises its
            // window; snd_nxt_ advances with the byte so the peer's ACK
            // acknowledges the probe as a valid cumulative ACK. The byte is
            // real buffered data (the first pending_send_ byte, consumed) -
            // never a literal 0x00, which would corrupt the byte stream when
            // the window reopens (see below).
            if (TcpState::kEstablished == state_ || TcpState::kCloseWait == state_) {
                // RFC 1122 s4.2.2.17: the persist probe carries ONE byte so the
                // peer re-advertises its window. The byte must be the FIRST
                // UNACKED byte (snd_una_): when unacked data exists, the
                // receiver's gap starts at snd_una_, and a probe past it
                // (pending_send_[0]) arrives out-of-order, gets buffered and
                // NEVER reopens the window - a silent zero-window deadlock.
                Byte probe_byte = 0;
                UInt32 probe_seq = 0;
                bool consume_pending = false;
                if (!retrans_queue_.empty() && !retrans_queue_.front().data.IsEmpty()) {
                    probe_seq = snd_una_;
                    // The probe byte must be the FIRST UNACKED PAYLOAD byte.
                    // seg.data is a complete IP+TCP+payload packet (see the
                    // RetransmitFront rebuild at tcp_fsm.cpp:1034-1058), so Data()[0]
                    // is the IP header - sending that (0x45/0x60) would pollute
                    // the byte stream when the window reopens. Offset to the
                    // payload start exactly like RetransmitFront does.
                    const buf::BufRef& front_data = retrans_queue_.front().data;
                    const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                    const UInt32 tcp_hdr_len =
                        static_cast<UInt32>(front_data.Data()[ip_hdr_len + 12] >> 4) * 4;
                    if (front_data.Len() > ip_hdr_len + tcp_hdr_len) {
                        probe_byte = front_data.Data()[ip_hdr_len + tcp_hdr_len];  // the missing byte
                    }
                } else if (!pending_send_.empty()) {
                    // All previously sent bytes were ACKed: probe the FIRST
                    // buffered byte. It is CONSUMED from pending_send_ - the
                    // window-reopen flush then continues from byte 2. A probe
                    // carrying a literal 0x00 without consuming pending_send_
                    // delivered [0x00 x n] + payload once the window reopened
                    // (n phantom bytes that were never application data).
                    probe_seq = snd_nxt_;
                    probe_byte = pending_send_[0];
                    consume_pending = true;
                }
                if (0 != probe_seq || consume_pending) {
                    buf::BufRef packet = BuildSegmentPacket(local_, remote_, probe_seq, rcv_nxt_,
                                                            kFlagAck | kFlagPsh, &probe_byte, 1,
                                                            AdvertisedWindow(), rcv_wscale_,
                                                            Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                    if (!packet.IsEmpty()) {
                        if (consume_pending) {
                            pending_send_.erase(pending_send_.begin());  // probe consumes the first byte
                            // The probe byte is REAL data (consumed above), so it
                            // must be recoverable: queue it in retrans_queue_ like
                            // any other segment (mirror of SendData below). A
                            // fire-and-forget probe that is LOST on the wire would
                            // permanently delete that byte from the stream - the
                            // peer stalls at the gap forever while the recovery
                            // flush starts past it and kMaxDataRetries kills the
                            // connection. The old B3 rationale against queueing
                            // (RTO double-firing with persist / burning the budget
                            // on a live zero-window peer) is stale: the BUG-A
                            // zero-window skip in RetransmitFront makes the RTO a
                            // re-arm-only no-op while the window stays zero, and
                            // the window-recovery ACK clears persist_deadline_
                            // before any flush can race it.
                            SentSeg seg;
                            seg.seq = probe_seq;
                            seg.len = 1;
                            seg.sent_at = now;
                            seg.rto = 0;
                            seg.sent_delivered = cc_.delivered;
                            seg.sent_delivered_pkts = cc_.delivered_pkts;
                            seg.pkt_count = PktCount(seg.len, peer_mss_);
                            seg.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                            // The probe consumes a NEW sequence byte (real
                            // application data), so it is not a retransmission.
                            const bool pipe_empty = (0 == PipeInFlightBytes());
                            seg.data = std::move(packet);  // retain for zero-copy retransmit
                            NotifyTxStart(pipe_empty);
                            if (sink_) {
                                sink_(seg.data.Clone());
                            }
                            // Account BEFORE the move (see the SendData path).
                            PipeAccountSeg(seg, +1);
                            retrans_queue_.push_back(std::move(seg));
                            if (1 == retrans_queue_.size()) {
                                ArmRetransmit(now);
                                first_outstanding_ = now;  // TCP_USER_TIMEOUT anchor (Karn-immune)
                            }
                            // snd_nxt_ advances with the byte, so the peer's ACK
                            // of the probe byte is a valid cumulative ACK that
                            // advances snd_una_ and, once the window re-opens,
                            // stops persist.
                            snd_nxt_ += 1;
                            // Kernel tcp_packets_in_flight(tp) = packets_out - (sacked_out + lost_out)
                // + retrans_out (tcp_h_66.h:1198-1220). The raw snd_nxt-snd_una
                // distance counts SACKed and LOST bytes as in flight, so every
                // CC consumer (tcp_cwnd_reduction's cwnd = inflight + sndcnt,
                // KCC packet_conservation, BBR's bdp gate) saw an inflated
                // pipe during recovery (audit B5-D3 / B6-D1).
                cc_.inflight = PipeInFlightBytes();
                        } else {
                            // Unacked-data probe: re-probe the missing byte. It
                            // is already accounted in retrans_queue_ (no new
                            // data, no snd_nxt_ advance); the segment that
                            // carries it retransmits the full range once the
                            // window reopens. Clone so retrans_queue_ keeps the
                            // original for zero-copy retransmit.
                            SentSeg& front = retrans_queue_.front();
                            front.sent_delivered = cc_.delivered;
                            front.sent_delivered_pkts = cc_.delivered_pkts;
                            front.pkt_count = PktCount(front.len, peer_mss_);
                            front.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                            const Byte old_is_retrans = front.is_retrans;
                            front.is_retrans = 1;
                            // TCPCB_SACKED_RETRANS just got set on a segment
                            // that may have had it clear: re-account its pipe
                            // contribution, or retrans_out and the pipe sum
                            // disagree.
                            PipeReaccountSeg(front, front.sacked, front.lost,
                                             old_is_retrans);
                            // Kernel tcp_event_data_sent: a persist
                            // re-probe carries data, so it is a TX_START candidate.
                            NotifyTxStart(0 == PipeInFlightBytes());
                            if (sink_) {
                                sink_(std::move(packet));
                            }
                            // Kernel tcp_retransmit_skb (tcp_output_66.c:3325):
                            // tp->total_retrans += tcp_skb_pcount(skb).
                            total_retrans_pkts_ += front.pkt_count;
                        }
                        // The probe drained the last buffered byte while a
                        // deferred FIN (Close with buffered data) is pending:
                        // send it now, exactly as a successful FlushPendingSend
                        // would. Without this the close_pending_ FIN strands -
                        // OnAckReceived only flushes (and thus calls
                        // MaybeFinishClose) when pending_send_ is non-empty.
                        MaybeFinishClose(now);
                    }
                } else {
                    // No buffered data: a pure ACK window probe (seq = snd_nxt_,
                    // no data byte) asks the peer to re-advertise its window
                    // without consuming a sequence number. snd_nxt_ is NOT
                    // advanced - there is no byte to account for and an
                    // empty-pending connection has nothing to flush.
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                }
                // The re-arm is gated on the same state check as the probe:
                // a closing state (FinWait1/LastAck/Closing) never sends a
                // probe (BUG-B), so re-arming would spin the persist timer
                // forever (doubling to the 60 s ceiling) with the connection
                // stuck in the closing state, timers_dirty_ forever, waiting
                // on a probe it will never emit. Disarm instead: the RTO
                // timer owns the closing state, and RetransmitFront now
                // consumes the retry budget at a zero window so the slot is
                // eventually reclaimed.
                persist_deadline_ = now + persist_interval_;
                timers_dirty_.store(true, std::memory_order_relaxed);
                // RFC 1122: exponential backoff to a 60 s ceiling. The
                // pre-check alone lets a 40 s interval double to 80 s - clamp
                // AFTER the double, mirroring RetransmitFront's seg.rto
                // pattern (tcp_fsm.cpp:1075-1082).
                if (persist_interval_ < kMaxRto) {
                    persist_interval_ *= 2;
                    if (persist_interval_ > kMaxRto) {
                        persist_interval_ = kMaxRto;
                    }
                }
            } else {
                // BUG-B: closing states never emit a probe - stop the persist
                // timer entirely instead of re-arming it (see comment above).
                persist_deadline_ = 0;
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
        }

        UInt32 TcpConn::OnPoll(TimePoint now) noexcept {
            // One lock for the whole poll: the per-connection timer sweep in
            // XtcpStack::PollAckTimers used four locking getters per
            // connection per round; hot paths with thousands of connections
            // paid four uncontended (but non-free) lock cycles each.
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            UInt32 fired = 0;
            // Bug(close): a closed connection must not emit anything (retx,
            // delayed ACK, persist probe, keepalive). Transition(kClosed)
            // already disarmed these timers; this guard is the belt-and-
            // suspenders for any state that slipped in without a Transition.
            // TIME-WAIT is terminating too: a delayed ACK armed before the
            // close handshake would otherwise fire a gratuitous ACK during
            // 2MSL (RFC 793 allows only re-ACKing stray retransmits, which
            // the kTimeWait OnSegment branch handles). FIN-WAIT-1/2 and
            // LAST-ACK may still legitimately ACK received data, so only
            // CLOSED and TIME-WAIT are blocked here.
            if (TcpState::kClosed == state_ || TcpState::kTimeWait == state_) {
                return 0;
            }
            // TCP_USER_TIMEOUT: abort when the oldest unacknowledged segment
            // has been outstanding longer than the bound (Linux parity; 0 =
            // disabled, the RTO-retry budget still bounds the connection).
            if (0 < user_timeout_us_ && 0 != first_outstanding_ &&
                now >= first_outstanding_ + user_timeout_us_) {
                Transition(TcpState::kClosed);
                NotifyStateChanged();  // timer-driven: the app must see the abort
                timers_dirty_.store(true, std::memory_order_relaxed);
                rto_deadline_ = 0;
                persist_deadline_ = 0;
                ++fired;
                return fired;
            }
            if (0 != ack_deadline_ && ack_deadline_ <= now) {
                if (ack_pending_) {
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                    ack_pending_ = false;
                    ack_count_ = 0;
                    ack_deadline_ = 0;
                    ++fired;
                }
            }
                if (0 != rto_deadline_ && rto_deadline_ <= now) {
                OnRetransmitTimer(now);  // re-locks (recursive); fires SYN/FIN/data retx
                ++fired;
            }
            // RFC 8985 TLP: the probe fires before the RTO when the tail
            // segment is still unacknowledged and the sender is not in
            // recovery - retransmit the tail (the most recent in-flight
            // segment) so the peer's ACK unblocks the stream without the
            // RTO's window cut. A retransmit timer about to fire wins: the
            // RTO handles it (the TLP must not add a spurious duplicate).
            if (tlp_armed_ && 0 != tlp_deadline_ && tlp_deadline_ <= now &&
                !fast_recovery_ && !retrans_queue_.empty() &&
                (0 == rto_deadline_ || now < rto_deadline_)) {
                // Retransmit the tail: the re-emission mirrors RetransmitFront's
                // emit path (clone + sink) but does not consume the retry
                // budget or back off the RTO - the TLP is a probe, not a loss
                // verdict.
                SentSeg& tail = retrans_queue_.back();
                if (0 < tail.len && 0 < snd_wnd_) {
                    buf::BufRef copy = tail.data.Clone();
                    if (!copy.IsEmpty() && sink_) {
                        // TLP re-sends existing data: it is a retransmission
                        // for the delayed-ACK heuristic even though retries
                        // (the RTO budget) deliberately stays untouched.
                        tail.sent_delivered = cc_.delivered;
                        tail.sent_delivered_pkts = cc_.delivered_pkts;
                        tail.pkt_count = PktCount(tail.len, peer_mss_);
                        tail.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                        const Byte old_is_retrans = tail.is_retrans;
                        tail.is_retrans = 1;
                        // See the persist path: TCPCB_SACKED_RETRANS may have
                        // been clear, so the pipe term needs re-accounting.
                        PipeReaccountSeg(tail, tail.sacked, tail.lost, old_is_retrans);
                        // Kernel tcp_send_loss_probe -> tcp_retransmit_skb:
                        // tp->total_retrans += tcp_skb_pcount(skb).
                        // MUST run BEFORE sink_: a synchronous backend delivers
                        // the peer's ACK reentrantly inside sink_(), which can
                        // pop (and free) this tail segment - reading
                        // tail.pkt_count afterwards is a heap use-after-free
                        // (ASan: test_tso_rto, tcp_fsm.cpp:4438).
                        total_retrans_pkts_ += tail.pkt_count;
                        // Kernel tcp_event_data_sent: every data skb counts,
                        // retransmissions included (the TLP is one).
                        NotifyTxStart(0 == PipeInFlightBytes());
                        sink_(std::move(copy));
                        ++retransmit_count_;
                    }
                }
                tlp_armed_ = false;
                tlp_deadline_ = 0;
                ++fired;
            }
            if (0 != persist_deadline_ && persist_deadline_ <= now) {
                OnPersistTimer(now);  // re-locks (recursive); zero-window probe
                ++fired;
            }
            if (0 < pending_send_.size()) {
                FlushPendingSend(now);  // buffered sends ride the freed window
            }
            // Keepalive (Linux TCP_KEEPIDLE semantics): probe when idle,
            // abort after cnt unanswered probes. Established only: in
            // CLOSE-WAIT the peer already sent FIN and is shutting down (a
            // pure-ACK probe would go unanswered by a FIN-WAIT peer and trip
            // a false abort); CLOSE-WAIT is ended by the app's Close() and
            // reclaims via the normal close path.
            if (0 < keepalive_idle_ && TcpState::kEstablished == state_) {
                const UInt64 idle_us = (0 < keepalive_probes_) ? keepalive_intvl_ : keepalive_idle_;
                if (0 == last_rx_ || now - last_rx_ >= idle_us) {
                    if (keepalive_cnt_ <= keepalive_probes_) {
                        Abort();  // peer is gone: RST and reclaim
                        NotifyStateChanged();  // timer-driven: the app must see the abort
                        timers_dirty_.store(true, std::memory_order_relaxed);
                        ++fired;
                    } else {
                        // Probe: ACK with seq = snd_nxt_-1 (Linux tcp_keepalive).
                        // RFC 3168 s6.1.3: echo ECE while CE was seen (the
                        // probe is an ACK like any other).
                        SendSegment(snd_nxt_ - 1, rcv_nxt_, AckFlags(), NULLPTR, 0);
                        ++keepalive_probes_;
                        last_rx_ = now;
                        timers_dirty_.store(true, std::memory_order_relaxed);
                        ++fired;
                    }
                }
            }
            // RFC 1191 periodic MTU re-probe: the path may have grown; restore
            // the negotiated MSS. A new ICMP "fragmentation needed" lowers it
            // again (closed loop). Established only: keepalive may Abort
            // (kClosed) earlier in this same poll round, and a closed
            // connection must not have its fields rewritten (mirror of the
            // keepalive state gate above).
            if (TcpState::kEstablished == state_ && 0 != mtu_probe_deadline_ &&
                mtu_probe_deadline_ <= now &&
                0 != orig_peer_mss_ && peer_mss_ < orig_peer_mss_) {
                // Restore through the TCP_MAXSEG ceiling: a user-set
                // ceiling below the negotiated MSS must keep binding the
                // restored value (Linux tcp_current_mss semantics), or a
                // reduce -> restore cycle would exceed user_mss_.
                UInt32 restored = orig_peer_mss_;
                if (0 < user_mss_ && user_mss_ < restored) {
                    restored = user_mss_;
                }
                peer_mss_ = static_cast<UInt16>(restored);
                cc_.mss = peer_mss_;
                mtu_probe_deadline_ = 0;
                timers_dirty_.store(true, std::memory_order_relaxed);
                ++fired;
            }
            // Linux tcp_fin_timeout: a peer that never sends its FIN would
            // hold FIN-WAIT-2 forever; reclaim after the timeout.
            if (TcpState::kFinWait2 == state_ && 0 != finwait2_deadline_ &&
                finwait2_deadline_ <= now) {
                Transition(TcpState::kClosed);
                NotifyStateChanged();  // timer-driven: the app must see the close
                timers_dirty_.store(true, std::memory_order_relaxed);
                ++fired;
            }
            // Idle fast path: with nothing armed or buffered, the stack-wide
            // sweep skips this connection without locking. Closing states
            // (CLOSED / LAST-ACK / FIN-WAIT-2 / TIME-WAIT) stay dirty so the
            // reclamation pass in PollAckTimers sees them every round.
            const bool closing = (TcpState::kClosed == state_ || TcpState::kLastAck == state_ ||
                                  TcpState::kFinWait2 == state_ || TcpState::kTimeWait == state_);
            if (0 == ack_deadline_ && 0 == rto_deadline_ && 0 == persist_deadline_ &&
                0 == tlp_deadline_ && 0 == pending_send_.size() && 0 == keepalive_idle_ &&
                0 == mtu_probe_deadline_ && !closing) {
                timers_dirty_.store(false, std::memory_order_relaxed);
            }
            return fired;
        }

        void TcpConn::Flush(TimePoint now) noexcept {
            // Sends buffered data after a window update; on SynSent/SynRcvd
            // the queued app data is flushed on Established (FlushPendingSend).
            if (0 < pending_send_.size()) {
                FlushPendingSend(now);
            }
            // Window-driven resend is handled by the caller retrying SendData
            // after window updates; Flush exists for API symmetry.
            (void)now;
        }

        void TcpConn::FlushPendingSend(TimePoint now) noexcept {
            if (pending_send_.empty() || (TcpState::kEstablished != state_ && TcpState::kCloseWait != state_)) {
                tx_waiter_.Cancel();
                return;
            }
            struct BurstGuard {
                buf::TxWaiter& waiter;
                ~BurstGuard() noexcept { waiter.ReleaseUnused(); }
            } burst_guard{tx_waiter_};
            std::vector<Byte> data;
            data.swap(pending_send_);
            for (UInt32 off = 0; off < data.size();) {
                // Pacing gate: a rate-limited CC must not have its buffered
                // sends flushed past the pacing deadline (SendData already
                // gates, FlushPendingSend must too - otherwise the ACK clock
                // flushes the whole buffer in one round).
                if (0 < cc_.pacing_rate && now < pacing_deadline_) {
                    pending_send_.assign(data.begin() + off, data.end());
                    return;
                }
                UInt32 n = static_cast<UInt32>(data.size() - off);
                const UInt64 cwnd = static_cast<UInt64>(cc_.snd_cwnd) * peer_mss_;
                UInt32 limit = snd_buf_;
                if (cwnd < limit) {
                    limit = static_cast<UInt32>(cwnd);
                }
                if (snd_wnd_ < limit) {
                    limit = snd_wnd_;
                }
                if (fast_recovery_) {
                    // RFC 6675 pipe gate (mirror of SendData): during
                    // recovery the pipe replaces the cwnd - flush while
                    // pipe < ssthresh, bounded by the peer window. Without
                    // this the ACK-driven flush would push the whole buffer
                    // past ssthresh during recovery.
                    const UInt64 ssthresh_bytes = static_cast<UInt64>(cc_.snd_ssthresh) * peer_mss_;
                    const UInt64 pipe = PipeBytes();
                    if (pipe >= ssthresh_bytes) {
                        pending_send_.assign(data.begin() + off, data.end());
                        return;  // pipe full: the ACK clock reopens it
                    }
                    limit = (snd_wnd_ < snd_buf_) ? snd_wnd_ : snd_buf_;
                    if (n > ssthresh_bytes - pipe) {
                        n = static_cast<UInt32>(ssthresh_bytes - pipe);
                    }
                }
            const UInt32 inflight = snd_nxt_ - snd_una_;
                if (limit <= inflight) {
                    // Window closed mid-flush: re-queue the remainder.
                    pending_send_.assign(data.begin() + off, data.end());
                    // RFC 1122 s4.2.2.17: data buffered behind a zero window
                    // MUST be probed - a lost window-update ACK must not
                    // deadlock the flow. The handshake-completion flush can
                    // reach this branch too (data buffered during SYN_SENT
                    // completing against a zero window), which previously
                    // armed no persist and sent NOTHING on the wire (audit M1).
                    if (0 == snd_wnd_ && 0 == persist_deadline_) {
                        // RFC 1122 s4.2.2.17: data buffered behind a zero
                        // window MUST be probed - a lost window-update ACK
                        // must not deadlock the flow. The handshake-completion
                        // flush can reach this branch too (data buffered
                        // during SYN_SENT completing against a zero window),
                        // which previously armed no persist and sent NOTHING
                        // on the wire (audit M1). Arm ONLY when not already
                        // armed: this branch runs on every poll round (OnPoll
                        // re-flushes pending_send_), and a 'now < deadline'
                        // re-arm would slide the deadline 1s into the future
                        // forever - the probe would never fire.
                        persist_deadline_ = now + persist_interval_;
                        timers_dirty_.store(true, std::memory_order_relaxed);
                    }
                    return;
                }
                if (n > limit - inflight) {
                    n = limit - inflight;
                }
                // One segment per flush step: MSS-sized on the wire (DF +
                // peer MSS negotiation). MD5 connections cap at MSS-20 so the
                // option is never rebuilt by tx-boundary segmentation.
                if (n > peer_mss_) {
                    n = peer_mss_;
                }
                if (Md5Enabled()) {
                    // MD5 connections cap at MSS-20 so the option is never
                    // rebuilt by tx-boundary segmentation. SetPeerMss clamps
                    // the negotiated MSS to >= 256, so MSS-20 cannot wrap.
                    const UInt32 md5_cap = (peer_mss_ > 20) ? (peer_mss_ - 20) : 0;
                    if (n > md5_cap) {
                        n = md5_cap;
                    }
                }
                // No Nagle gate here: this is the ACK-driven flush path, and
                // Nagle (RFC 896) applies only at the application send entry.
                // Gating the tail here deadlocks: after a partial ACK leaves
                // inflight >= MSS with a <MSS tail buffered, the tail never
                // goes out, the peer never ACKs again, and the pipe stalls
                // forever (Linux tcp_push only Nagles fresh sends, never the
                // ACK-clock refill).
                const UInt32 seq = snd_nxt_;
                // Preserve PUSH at the end of this buffered byte range, not
                // on every MSS-sized segment. Besides matching TCP push
                // semantics, this keeps adjacent data segments eligible for
                // downstream VNET GSO coalescing.
                const UInt16 data_flags = kFlagAck |
                    ((off + n == data.size()) ? kFlagPsh : 0) |
                    (cwr_pending_ ? kFlagCwr : 0);
                buf::BufRef packet;
                {
                    buf::TxAcquireScope tx_class(&tx_waiter_);
                    packet = BuildSegmentPacket(local_, remote_, seq, rcv_nxt_,
                                                        data_flags, data.data() + off, n,
                                                        AdvertisedWindow(), rcv_wscale_,
                                                        Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                }
                if (packet.IsEmpty()) {
                    MarkPoolLimited(inflight);
                    pending_send_.insert(pending_send_.begin(), data.begin() + off, data.end());
                    return;
                }
                cwr_pending_ = false;  // CWR emitted on this data segment (RFC 3168 s6.1.2)
                // Kernel CA_EVENT_TX_START gate: tcp_packets_in_flight == 0
            // (tcp_output_v66.c:167-168), evaluated at the emit point.
            const bool pipe_empty = (0 == PipeInFlightBytes());
                // RFC 6937 PRR: the ACK-driven flush also spends recovery
                // credit. PACKET domain (kernel prr_out += tcp_skb_pcount).
                if (fast_recovery_) {
                    prr_out_ += PktCount(n, peer_mss_);
                }
                snd_nxt_ += n;
                SentSeg seg;
                seg.seq = seq;
                seg.len = n;
                seg.sent_at = now;
                seg.rto = 0;
                seg.sent_delivered = cc_.delivered;
                seg.sent_delivered_pkts = cc_.delivered_pkts;
                seg.pkt_count = PktCount(n, peer_mss_);
                seg.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                seg.data = std::move(packet);
                NotifyTxStart(pipe_empty);
                // D12: push before sink (mirror of the SendData direct-send
                // fix) - a synchronous backend delivers the peer's ACK
                // reentrantly inside sink_(), and a queue missing this
                // segment would advance snd_una_ past it, never reaping it.
                // Account BEFORE the move (see the SendData path).
                PipeAccountSeg(seg, +1);
                retrans_queue_.push_back(std::move(seg));
                if (1 == retrans_queue_.size()) {
                    ArmRetransmit(now);
                    first_outstanding_ = now;  // TCP_USER_TIMEOUT anchor (Karn-immune)
                }
                if (sink_) {
                    sink_(retrans_queue_.back().data.Clone());  // transmit now (zero-copy retx ref held)
                }
                // Kernel tcp_packets_in_flight(tp) = packets_out - (sacked_out + lost_out)
                // + retrans_out (tcp_h_66.h:1198-1220). The raw snd_nxt-snd_una
                // distance counts SACKed and LOST bytes as in flight, so every
                // CC consumer (tcp_cwnd_reduction's cwnd = inflight + sndcnt,
                // KCC packet_conservation, BBR's bdp gate) saw an inflated
                // pipe during recovery (audit B5-D3 / B6-D1).
                cc_.inflight = PipeInFlightBytes();
                cc_.lsndtime = now / 1000;
                if (0 < cc_.pacing_rate) {
                    pacing_deadline_ = now + (static_cast<UInt64>(n) * 1000000ull) / cc_.pacing_rate;
                }
                off += n;
            }
            // Bug(close): when Close() deferred the FIN because buffered data
            // was window-constrained, this drain is what unlocks it - the FIN
            // must follow every data byte on the wire (RFC 793).
            if (pending_send_.empty()) tx_waiter_.Cancel();
            MaybeFinishClose(now);
        }

        void TcpConn::MaybeFinishClose(TimePoint now) noexcept {
            if (!close_pending_ || !pending_send_.empty()) {
                return;
            }
            // The buffered data drained: send the FIN that Close() deferred.
            // The sequence mirrors Close()'s direct path (FIN then state).
            if (TcpState::kEstablished == state_ || TcpState::kSynRcvd == state_) {
                close_pending_ = false;
                SendSegment(snd_nxt_, rcv_nxt_, kFlagFin | kFlagAck, NULLPTR, 0);
                ++snd_nxt_;
                Transition(TcpState::kFinWait1);
                ArmRetransmit(now);
            } else if (TcpState::kCloseWait == state_) {
                close_pending_ = false;
                SendSegment(snd_nxt_, rcv_nxt_, kFlagFin | kFlagAck, NULLPTR, 0);
                ++snd_nxt_;
                Transition(TcpState::kLastAck);
                ArmRetransmit(now);
            }
            // Any other state (e.g. RST already moved us to kClosed, which
            // Transition() cleared close_pending_ for) needs no FIN.
        }

        void TcpConn::NotifyStateChanged() noexcept {
            if (state_change_cb_) {
                state_change_cb_(state_);
            }
        }

        TcpConn::ConnCheckpoint TcpConn::MakeCheckpoint() const noexcept {
            // Migration runs on a DIFFERENT thread than the data path
            // (scheduler Checkpoint/Restore), and it copies the retransmission
            // queue (BufRef::Clone -> pool allocation) while ApplyCheckpoint
            // may now re-init a CC plugin (KccInit -> new KccState + entropy).
            // Both are unsynchronized against OnSegment/SendData unless the
            // connection lock is taken here (audit E, batch 5). syncobj_ is
            // mutable, so the const method can lock it.
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            ConnCheckpoint ckpt;
            ckpt.state = state_;
            ckpt.snd_una = snd_una_;
            ckpt.snd_nxt = snd_nxt_;
            ckpt.rcv_nxt = rcv_nxt_;
            ckpt.snd_wnd = snd_wnd_;
            ckpt.window = window_;
            ckpt.rcv_wnd = rcv_wnd_;
            ckpt.rcv_wscale = rcv_wscale_;
            ckpt.snd_wscale = snd_wscale_;
            ckpt.rto = rto_;
            ckpt.srtt = srtt_;
            ckpt.rttvar = rttvar_;
            // The send-side transmission state: without the retransmission
            // queue a migrated connection cannot retransmit its in-flight
            // segments (the RTO path no-ops on an empty queue) and the
            // buffered application bytes would be lost. BufRef is move-only,
            // so each segment's payload is cloned into an independent pool
            // reference - the checkpoint and the source connection stay
            // valid independently.
            ckpt.pending_send = pending_send_;
            ckpt.retrans_queue.clear();
            for (const SentSeg& s : retrans_queue_) {
                SentSeg c;
                c.seq = s.seq;
                c.len = s.len;
                c.sent_at = s.sent_at;
                c.rto = s.rto;
                c.retries = s.retries;
                c.sacked = s.sacked;
                c.pkt_count = s.pkt_count;
                c.lost = s.lost;
                // See ApplyCheckpoint: the retransmit marker and the
                // retirement flag must survive, but the absolute delivery
                // watermark must not (the restore starts a new epoch).
                c.is_retrans = s.is_retrans;
                c.retrans_out_retired = s.retrans_out_retired;
                c.data = const_cast<buf::BufRef&>(s.data).Clone();
                ckpt.retrans_queue.push_back(std::move(c));
            }
            return ckpt;
        }

        void TcpConn::ApplyCheckpoint(const ConnCheckpoint& ckpt) noexcept {
            // Symmetric with MakeCheckpoint: the restore rewrites every send
            // scalar, clones the checkpoint's segments and may re-init the CC
            // plugin (heap allocation + entropy seed), so it must hold the
            // connection lock against the data path (audit E, batch 5).
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            state_ = ckpt.state;
            snd_una_ = ckpt.snd_una;
            snd_nxt_ = ckpt.snd_nxt;
            rcv_nxt_ = ckpt.rcv_nxt;
            snd_wnd_ = ckpt.snd_wnd;
            window_ = ckpt.window;
            rcv_wnd_ = ckpt.rcv_wnd;
            rcv_wscale_ = ckpt.rcv_wscale;  // keep the negotiated receive scale (RFC 7323)
            snd_wscale_ = ckpt.snd_wscale;
            rto_ = ckpt.rto;
            srtt_ = ckpt.srtt;
            rttvar_ = ckpt.rttvar;
            // The checkpoint carries no out-of-order reassembly buffer (ooo_
            // is deliberately dropped: the peer retransmits what it sent past
            // the frontier), so the byte counter that mirrors it must be
            // cleared too. Leaving it set would make AdvertisedWindow() report
            // window_ - ooo_bytes_ forever, i.e. permanently shrink the receive
            // window by data that no longer exists.
            ooo_.clear();
            ooo_bytes_ = 0;
            // Migration starts a NEW delivered epoch: the checkpoint does not
            // carry cc_.delivered nor the per-segment send snapshots (both
            // default to 0). Carrying a stale epoch would make every ACK look
            // like a new delivery round. Reset the accumulators explicitly.
            cc_.delivered = 0;
            cc_.delivered_pkts = 0;
            cc_.delivered_mstamp = 0;
            cc_.app_limited = 0;
            cc_.lost = 0;
            // Packet-domain twin of cc_.lost (kernel tp->lost): it is a
            // per-sample accumulator consumed by EmitRateSample, so a migrated
            // flow must not inherit the source's freshly-marked-loss count
            // (that would subtract phantom segments from the new flow's cwnd
            // on its first ACK). max_pacing_rate is deliberately NOT reset:
            // it is a user policy (SO_MAX_PACING_RATE), not connection state.
            cc_.lost_pkts = 0;
            last_rate_sample_ = 0;
            last_delivered_ = 0;
            last_delivered_pkts_ = 0;
            batch_prior_delivered_ = 0;
            batch_prior_delivered_pkts_ = 0;
            lost_out_pkts_ = 0;
            retrans_out_pkts_ = 0;
            // Kernel tp->total_retrans / tp->dsack_dups / tp->max_window are
            // per-connection counters; a migrated flow restarts from the fresh
            // values (the checkpoint carries no retransmission history).
            total_retrans_pkts_ = 0;
            dsack_dups_ = 0;
            max_window_ = (0 < snd_wnd_) ? snd_wnd_ : kDefaultWindow;
            // Transient send/receive flags belong to the OLD connection: the
            // destination may have queued a delayed ACK, a D-SACK, or a
            // pending CWR echo of its own. Carrying any of them past the
            // restore makes the migrated flow emit control flags it has no
            // reason to send - a stale cwr_pending_ in particular tells the
            // peer we reduced the window for congestion that never happened on
            // this flow. Their deadlines go with them.
            ack_pending_ = false;
            ack_count_ = 0;
            ack_deadline_ = 0;
            quickack_ = false;
            cwr_pending_ = false;
            ecn_ce_seen_ = false;
            ecn_reduce_at_ = 0;
            dsack_pending_ = false;
            dsack_left_ = 0;
            dsack_right_ = 0;
            dupack_count_ = 0;
            dupack_deadline_ = 0;
            challenge_count_ = 0;
            challenge_deadline_ = 0;
            ack_not_dup_ = false;
            // The checkpoint carries no congestion state, so every episode /
            // undo field must be reset to its "no episode" value. Otherwise
            // the TARGET connection's previous values leak into the migrated
            // one: a stale rto_pending_ would keep the DSACK/Eifel gate
            // closed, a stale undo_retrans_ would feed batch 2's may-undo
            // gate, and a stale ca_state would make EndCwndReduction's
            // `2 == ca_state` guard fire on a connection that is not in CWR.
            // Batch 5 (D10) owns the complete congestion-view reset; this is
            // the batch-1 subset it builds on.
            fast_recovery_ = false;
            sack_retx_next_ = 0;
            high_seq_ = 0;
            prior_cwnd_ = 0;
            prior_ssthresh_ = 0;
            undo_marker_ = false;
            undo_retrans_ = -1;
            episode_undone_ = true;
            rto_pending_ = false;
            rto_ts_val_ = 0;
            retrans_stamp_ts_ = 0;
            rto_retx_end_ = 0;
            icsk_retransmits_ = 0;   // kernel icsk_retransmits: new epoch
            cc_.ca_state = 0;
            cc_.prior_cwnd = 0;
            cc_.prior_ssthresh = 0;
            cc_.packet_conservation = 0;
            // Batch 5 (D10): the checkpoint carries NO congestion-control
            // view, so the migrated flow must restart from the "fresh
            // connection, Open state" values the TcpConn constructor uses
            // (tcp_fsm.cpp:896-903) instead of inheriting the destination's
            // Loss/Recovery window it cannot justify. Leaving snd_cwnd /
            // snd_ssthresh / prr_* / recover_fs_ / dup_acks_ in place let a
            // stale episode survive the restore and rewrite the migrated
            // window (audit D10, observed: cwnd stayed at the target's cut
            // value after ApplyCheckpoint).
            cc_.snd_cwnd = 10;                 // RFC 6928 initcwnd
            cc_.snd_ssthresh = 0x7FFFFFFF;     // unlimited until the first loss
            cc_.snd_cwnd_cnt = 0;
            cc_.pacing_rate = 0;
            recover_fs_ = 0;
            prr_delivered_ = 0;
            prr_out_ = 0;
            dup_acks_ = 0;
            fast_retransmit_seq_ = 0;
            pacing_deadline_ = 0;
            if (NULLPTR != cc_ops_ && NULLPTR != cc_ops_->init) {
                // Fresh plugin epoch. KCC's init resets prev_ca_state /
                // packet_conservation / full_bw (cc_kcc.cpp:770-789); CUBIC's
                // resets the epoch base; BBR's resets its cycle. Without this
                // a migrated KCC flow keeps packet_conservation=1 from the
                // source shard and never grows.
                cc_ops_->init(&cc_);
            }
            batch_app_limited_ = 0;
            batch_retrans_ = false;
            last_ack_delayed_ = false;
            pending_send_ = ckpt.pending_send;
            retrans_queue_.clear();
            // The queue is rebuilt from the checkpoint below; the pipe sums are
            // re-accumulated per restored segment.
            pipe_sacked_bytes_ = 0;
            pipe_lost_bytes_ = 0;
            pipe_retrans_bytes_ = 0;
            for (const SentSeg& s : ckpt.retrans_queue) {
                SentSeg c;
                c.seq = s.seq;
                c.len = s.len;
                c.sent_at = s.sent_at;
                c.rto = s.rto;
                c.retries = s.retries;
                c.sacked = s.sacked;
                c.pkt_count = s.pkt_count;
                c.lost = s.lost;
                // TCPCB_RETRANS and the retirement flag travel with the
                // segment: without is_retrans a migrated retransmit looks like
                // a first transmission, so popping it would neither decrement
                // retrans_out_pkts_ (permanently inflating the pipe) nor set
                // batch_retrans_ for the delayed-ACK heuristic.
                c.is_retrans = s.is_retrans;
                c.retrans_out_retired = s.retrans_out_retired;
                // The send-time delivery snapshots must NOT be carried: this
                // migration starts a NEW delivered epoch (cc_.delivered and
                // cc_.delivered_pkts above are reset to 0), so the source's
                // absolute watermark would be larger than the new epoch's
                // total. That poisons batch_prior_delivered_pkts_ (see the
                // popped_count block), making rs.prior_delivered_pkts exceed
                // rs.delivered_total_pkts and firing a spurious KCC round
                // boundary on the first ACK. They stay 0, like a segment that
                // has not been (re)transmitted in this epoch yet.
                c.app_limited = 0;
                c.data = const_cast<buf::BufRef&>(s.data).Clone();
                // Kernel tp->retrans_out / tp->lost_out are AGGREGATES over
                // the skb tags, not independent counters. The restore zeroed
                // both above (the checkpoint carries no connection history),
                // so they must be rebuilt from the tags that just arrived -
                // otherwise the queue and the counters disagree and a popped
                // retransmit would underflow the aggregate.
                if (0 != c.is_retrans && 0 == c.retrans_out_retired) {
                    retrans_out_pkts_ += c.pkt_count;
                }
                if (0 != c.lost) {
                    lost_out_pkts_ += c.pkt_count;
                }
                // Account BEFORE the move: the pipe sums are rebuilt from the
                // restored tags (the checkpoint starts a new epoch).
                PipeAccountSeg(c, +1);
                retrans_queue_.push_back(std::move(c));
            }
            if (0 < retrans_queue_.size()) {
                // In-flight segments survived the migration: the RTO must
                // drive their retransmission on this (possibly new) connection.
                ArmRetransmit(NowUs());
            } else if (0 < pending_send_.size()) {
                // Buffered data with nothing in flight: a fresh send window.
                if (0 == snd_wnd_ && 0 == persist_deadline_) {
                    persist_deadline_ = NowUs() + persist_interval_;
                }
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
            // A migrated connection must re-arm its reclamation timers: the
            // checkpoint does not carry deadlines, so a FIN-WAIT-2 or
            // TIME-WAIT connection would otherwise never be reclaimed (or be
            // reclaimed immediately) after a scheduler migration.
            if (TcpState::kFinWait2 == state_) {
                finwait2_deadline_ = NowUs() + finwait2_timeout_;
                timers_dirty_.store(true, std::memory_order_relaxed);
            } else if (TcpState::kTimeWait == state_) {
                EnterTimeWait(NowUs());
                // EnterTimeWait already flags timers_dirty_ itself (tcp.h:
                // 612, "Defensive: a future direct caller must not strand
                // the conn"); the explicit store below is defensive
                // redundancy - keep both so a future EnterTimeWait refactor
                // cannot strand the conn. ApplyCheckpoint writes state_
                // directly, so neither Transition() nor EnterTimeWait runs
                // on the migration path - this flag is what makes
                // PollAckTimers' fast path visit the conn and reclaim the
                // TIME-WAIT entry.
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
        }

        void TcpConn::SendChallengeAck() noexcept {
            // RFC 5961 �?/ Linux tcp_challenge_ack_limit: a spoofed flood of
            // out-of-window RSTs must NOT reflect 1:1 into challenge ACKs.
            // Allow up to kChallengeAckLimit per 1s window; excess challenges
            // are dropped silently (the connection is simply not closed).
            static constexpr UInt64 kChallengeAckWindowUs = 1000000;
            static constexpr UInt32 kChallengeAckLimit = 8;
            const TimePoint now = NowUs();
            if (now >= challenge_deadline_) {
                challenge_deadline_ = now + kChallengeAckWindowUs;
                challenge_count_ = 0;
            }
            if (challenge_count_ >= kChallengeAckLimit) {
                return;
            }
            ++challenge_count_;
            // RFC 3168 s6.1.3: every ACK echoes ECE while CE was seen and
            // CWR has not arrived (mirror of SendDupAck/SendAck).
            SendSegment(snd_nxt_ - 1, rcv_nxt_, AckFlags(), NULLPTR, 0);
        }

        void TcpConn::SendDupAck() noexcept {
            // RFC 5961-style rate limit for dup-ACKs on old/out-of-order data:
            // an on-path flood must not reflect 1:1 (Linux tcp_challenge_ack
            // semantics), but the limit is much higher than the RST challenge
            // (100/s) because fast-retransmit recovery needs a BURST of 3+
            // dup-ACKs at RTT cadence - 8/s would stall SACK recovery.
            // Independent of the RFC 5961 RST challenge state
            // (challenge_deadline_/challenge_count_): an OOO flood and an RST
            // flood interleaving must not suppress each other's ACKs.
            static constexpr UInt64 kDupAckWindowUs = 1000000;
            static constexpr UInt32 kDupAckLimit = 100;
            const TimePoint now = NowUs();
            if (now >= dupack_deadline_) {
                dupack_deadline_ = now + kDupAckWindowUs;
                dupack_count_ = 0;
            }
            if (dupack_count_ >= kDupAckLimit) {
                return;
            }
            ++dupack_count_;
            SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
        }

        void TcpConn::SendAck() noexcept {
            SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
        }

        void TcpConn::SendSyn() noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            // RFC 7323: offer window scaling in the SYN (our receive
            // capability; rcv_wscale_ is set at handshake completion iff the
            // peer answers WSOPT - the both-sides rule).
            // RFC 3168 s6.1.1: an ECN offer is ECE+CWR together - the ECE bit
            // alone is not a valid offer (Linux's server requires both).
            // RFC 7323: the SYN offers timestamps (tsval = the clock; the
            // peer's answer activates the option).
            const bool syn_ts = ts_enabled_ && 0 == Md5KeyLen();  // RFC 7323 offer, never on MD5 (RFC 2385 option space)
            syn_ts_offered_ = syn_ts;  // RFC 7323 both-sides rule: the peer's answer only activates if WE offered
            const UInt32 ts_val = syn_ts ? static_cast<UInt32>((NowUs() / 1000) & 0xFFFFFFFF) : 0;
            SendSegmentPacket(local_, remote_, iss_, 0,
                              kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                              NULLPTR, 0,
                              static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_,
                              kWindowScaleOffer, Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, false,
                              syn_ts, ts_val, 0, no_sack_permitted_);
            ArmRetransmit(NowUs());  // RFC 793: retransmit SYN on timeout
        }

        bool TcpConn::SendSynWithData(const Byte* data, UInt32 len) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            if (TcpState::kSynSent != state_) {
                return false;
            }
            // RFC 7413: the fast-open SYN carries the peer's TFO cookie
            // (obtained from a previous SYN+ACK) so the server can validate
            // the early data against a cookie instead of trusting any SYN.
            // The data is retained so a lost SYN retransmits with it.
            // With no early data, fall back to a plain SYN so the caller
            // cannot strand the connection in SYN-SENT.
            if (0 == len || NULLPTR == data) {
                const bool syn_ts = ts_enabled_ && 0 == Md5KeyLen();  // RFC 7323 offer, never on MD5 (RFC 2385 option space)
                syn_ts_offered_ = syn_ts;  // RFC 7323 both-sides rule
                const UInt32 ts_val = syn_ts ? static_cast<UInt32>((NowUs() / 1000) & 0xFFFFFFFF) : 0;
                SendSegmentPacket(local_, remote_, iss_, 0,
                                  kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                                  NULLPTR, 0,
                                  static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_,
                                  kWindowScaleOffer, Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, false,
                                  syn_ts, ts_val, 0, no_sack_permitted_);
                snd_nxt_ = iss_ + 1;
                ArmRetransmit(NowUs());
                return true;
            }
            tfo_syn_data_.assign(data, data + len);
            // RFC 7323 both-sides rule: the fast-open SYN carries no TSopt
            // (option space), so a peer's timestamped answer must not activate
            // the option unilaterally.
            syn_ts_offered_ = false;
            if (has_tfo_cookie_) {
                // Early data is new data on an otherwise empty pipe: the
                // kernel __tcp_transmit_skb path fires CA_EVENT_TX_START for
                // the first data segment too.
                const bool pipe_empty = (0 == PipeInFlightBytes());
                // Reentrancy (D12 order): advance snd_nxt_ BEFORE the sink
                // emits. A synchronous backend (in-memory/loopback peer)
                // answers the SYN+ACK reentrantly INSIDE sink_; if snd_nxt_
                // still covered only the SYN, that ACK would look like it
                // acknowledged unsent data (hdr.ack > snd_nxt_) and the
                // fast-open early bytes would be stranded.
                snd_nxt_ = iss_ + 1 + len;  // SYN occupies iss; data follows
                NotifyTxStart(pipe_empty);
                SendSegmentPacket(local_, remote_, iss_, 0,
                                  kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                                  data, len,
                                  static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_, kWindowScaleOffer,
                                  Md5Key(), Md5KeyLen(), NULLPTR, 0, tfo_cookie_, false, false, 0, 0,
                                  no_sack_permitted_);
            } else {
                // No cookie yet: an RFC 7413 server refuses SYN-carried data
                // it cannot validate (cookie-less data is a spoof vector), so
                // buffer the bytes and send a plain SYN; the data flushes once
                // the handshake completes (FlushPendingSend on Established).
                // Sending it in the SYN would strand it past snd_nxt_.
                // Reentrancy (D12 order): buffer and advance snd_nxt_ BEFORE
                // the sink emits - a synchronous SYN+ACK completes the
                // handshake inside sink_ and its FlushPendingSend must find
                // these bytes, or they would be queued after the flush and
                // never sent.
                snd_nxt_ = iss_ + 1;
                pending_send_.insert(pending_send_.end(), data, data + len);
                timers_dirty_.store(true, std::memory_order_relaxed);
                SendSegmentPacket(local_, remote_, iss_, 0,
                                  kFlagSyn | (ecn_requested_ ? (kFlagEce | kFlagCwr) : 0),
                                  NULLPTR, 0,
                                  static_cast<UInt16>(window_ >> kWindowScaleOffer), sink_,
                                  kWindowScaleOffer, Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR,
                                  false, false, 0, 0, no_sack_permitted_);
            }
            ArmRetransmit(NowUs());  // RFC 793: the fast-open SYN is retransmitted on timeout
            return true;
        }

        void TcpConn::SendSynAck() noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            // RFC 7413: the SYN+ACK carries a TFO cookie for this client,
            // keyed by the client address (remote_) - never the server's own
            // address (local_), or every client in a time bucket would get
            // the same cookie, allowing cross-IP replay.
            Byte cookie[8];
            UInt32 bound[4];
            TfoBoundAddr(bound);
            tfo_.Generate(bound, cookie);
            const bool syn_ts = ts_enabled_ && 0 == Md5KeyLen();  // RFC 7323 offer, never on MD5 (RFC 2385 option space)
            syn_ts_offered_ = syn_ts;  // RFC 7323 both-sides rule: the client's offer only activates if WE answered
            const UInt32 ts_val = syn_ts ? static_cast<UInt32>((NowUs() / 1000) & 0xFFFFFFFF) : 0;
            SendSegmentPacket(local_, remote_, iss_, rcv_nxt_,
                              kFlagSyn | kFlagAck | (ecn_requested_ ? kFlagEce : 0),
                              NULLPTR, 0, AdvertisedWindow(), sink_, rcv_wscale_,
                              Md5Key(), Md5KeyLen(), NULLPTR, 0, cookie, false,
                              syn_ts, ts_val, 0, !sack_ok_);
            ArmRetransmit(NowUs());  // RFC 793: retransmit SYN+ACK on timeout
        }

        void TcpConn::ArmWindowUpdateAck(TimePoint now) noexcept {
            ack_pending_ = true;
            ack_count_ = 1;
            if (0 == ack_deadline_) {
                ack_deadline_ = now + kDelayedAckMs * 1000;
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
        }

        void TcpConn::AcceptEarlyData(const Byte* data, UInt32 len) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            if (TcpState::kSynRcvd != state_ || 0 == len || NULLPTR == data) {
                return;
            }
            const UInt32 prev = rcv_nxt_;
            rcv_nxt_ += len;  // advance before callback: sends inside it must ACK the early data
            if (recv_cb_ && !recv_cb_(data, len)) {
                rcv_nxt_ = prev;  // backpressure: don't consume the early data
            rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                return;
            }
        }

        buf::BufRef TcpConn::BuildSynAckPacket(const Endpoint& local, const Endpoint& remote,
                                               UInt32 cookie, UInt32 ack, Byte wscale,
                                               const Byte* md5_key, UInt32 md5_key_len) noexcept {
            // Stateless SYN+ACK for SYN-cookie mode: MSS + SACK-permitted +
            // WSOPT options (mirrors the normal SYN+ACK layout). Stateless:
            // no conn exists yet, so the window is the protocol default.
            return BuildSegmentPacket(local, remote, cookie, ack,
                                      kFlagSyn | kFlagAck, NULLPTR, 0,
                                      static_cast<UInt16>(kDefaultWindow >> wscale),
                                      wscale, md5_key, md5_key_len);
        }

        void TcpConn::Close(TimePoint now) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            (void)now;
            // RFC 793: closing before Established aborts (never sent SYN, or
            // the handshake is still in flight - data was never flushed).
            if (TcpState::kSynSent == state_) {
                pending_send_.clear();
                Transition(TcpState::kClosed);
                NotifyStateChanged();  // the app must see the close
                return;
            }
            switch (state_) {
            case TcpState::kSynRcvd:
                // RFC 793 s3.8: a close in SYN-RECEIVED is an ABORT - send a
                // reset. The peer, still in SYN-SENT, ignores FINs (its
                // parser only answers SYN/SYN+ACK/RST), so a FIN here would
                // be dead on arrival: both sides would retransmit for
                // minutes before converging.
                pending_send_.clear();
                SendSegment(snd_nxt_, rcv_nxt_, kFlagRst | kFlagAck, NULLPTR, 0);
                Transition(TcpState::kClosed);
                NotifyStateChanged();  // the app must see the close
                break;
            case TcpState::kEstablished:
                // RFC 793: the FIN must follow all buffered data, so flush
                // any window-constrained sends first (the FIN's seq then
                // lands after them on the wire).
                if (0 < pending_send_.size()) {
                    FlushPendingSend(NowUs());
                }
                // Bug(close): a zero window (or pacing/cwnd limit) can leave
                // the flush with buffered bytes. Sending the FIN now strands
                // them: FinWait1/LastAck never flush pending_send_, so the
                // data would be silently dropped. Defer the FIN and let
                // MaybeFinishClose send it once the buffer drains.
                if (0 == pending_send_.size()) {
                    SendSegment(snd_nxt_, rcv_nxt_, kFlagFin | kFlagAck, NULLPTR, 0);
                    ++snd_nxt_;
                    Transition(TcpState::kFinWait1);
                    // RFC 793: a lost FIN must be retransmitted; the RTO timer
                    // (OnRetransmitTimer FinWait1 path) drives it.
                    ArmRetransmit(NowUs());
                } else {
                    close_pending_ = true;
                    if (0 == snd_wnd_ &&
                        (0 == persist_deadline_ || NowUs() < persist_deadline_)) {
                        // RFC 1122: probe the zero-window peer so a lost
                        // window-update ACK cannot deadlock the close.
                        persist_deadline_ = NowUs() + persist_interval_;
                    }
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
                break;
            case TcpState::kCloseWait:
                if (0 == pending_send_.size()) {
                    SendSegment(snd_nxt_, rcv_nxt_, kFlagFin | kFlagAck, NULLPTR, 0);
                    ++snd_nxt_;
                    Transition(TcpState::kLastAck);
                    ArmRetransmit(NowUs());
                } else {
                    // Same deferral as Established: CloseWait still sends data,
                    // so the FIN must not jump ahead of the buffered bytes.
                    close_pending_ = true;
                    if (0 == snd_wnd_ &&
                        (0 == persist_deadline_ || NowUs() < persist_deadline_)) {
                        persist_deadline_ = NowUs() + persist_interval_;
                    }
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
                break;
            default:
                break;
            }
        }

        void TcpConn::Abort() noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            // RFC 793: never send a RST for a connection that is already
            // closed, still in LISTEN, or in TIME-WAIT (2MSL). Aborting those
            // sends a RST the peer never asked for and revives a state machine
            // that has (or never) finished closing.
            if (TcpState::kClosed == state_ || TcpState::kTimeWait == state_ ||
                TcpState::kListen == state_) {
                return;
            }
            pending_send_.clear();
            SendSegment(snd_nxt_, rcv_nxt_, kFlagRst | kFlagAck, NULLPTR, 0);
            Transition(TcpState::kClosed);
        }

        void TcpConn::OnSegment(const Byte* data, UInt32 len, TimePoint now) noexcept {
            std::lock_guard<std::recursive_mutex> scope(syncobj_);
            TcpHdr hdr;
            if (!ParseTcp(data, len, hdr)) {
                return;
            }
            // RFC 2385: drop segments whose TCP-MD5 signature is invalid.
            if (Md5Enabled() && !VerifyMd5Segment(Md5Key(), Md5KeyLen(), local_, remote_,
                                                  const_cast<Byte*>(data), len)) {
                return;
            }
            // RFC 3168 s6.1.4: a CWR from the sender acknowledges our ECE
            // echo - stop echoing ECE once it is seen (the sender has cut
            // its window in response). Without this, a single CE-marked
            // packet leaves ecn_ce_seen_ set forever and every subsequent
            // ACK carries ECE, halving the peer's cwnd once per RTT
            // indefinitely (throughput collapse after one congestion event).
            if (hdr.IsCwr()) {
                ecn_ce_seen_ = false;
            }
            // Keepalive refresh moved into the per-state cases: only a
            // segment that PASSES seq/ack validation (a valid ACK or
            // in-order data) proves the peer alive. A rejected out-of-window
            // ACK, unexpected SYN, invalid RST or out-of-window old data must
            // NOT reset the probe counter - otherwise a half-dead peer that
            // emits junk segments never gets aborted (B1).
            const Byte* payload = data + hdr.payload_off;
            const UInt32 payload_len = len - hdr.payload_off;

            // RFC 7323 PAWS: once timestamps are active, a segment whose
            // TSval is older than TsRecent (RFC 1982 comparison, so the 2^31
            // wrap window applies) is a stale or replayed segment - the
            // protection against the 2^32 sequence wrap (a wrap at 100Gbps
            // takes ~34 seconds, and without PAWS a wrapped old segment is
            // indistinguishable from new data). The check runs on the
            // data-carrying states before any state change; the ACK-only
            // segments keep the PAWS-free path (their seq checks already
            // bound them).
            // Parse the option stream ONCE for the data-carrying paths (a
            // parse is pure read; sharing it halves the per-segment work on
            // timestamps-enabled connections where the same segment feeds
            // both the PAWS gate and the established SACK/ACK handling
            // below). Errors fall back to the zero-initialized TcpOpts, which
            // every consumer already treats as "no options".
            TcpOpts opts;
            const bool opts_parsed = ParseTcpOpts(data, len, hdr.hdr_len, opts);
            if (timestamps_ok_ && 0 < payload_len && opts_parsed && opts.has_timestamp) {
                const bool paws_state = TcpState::kEstablished == state_ ||
                    TcpState::kFinWait1 == state_ || TcpState::kFinWait2 == state_ ||
                    TcpState::kClosing == state_ || TcpState::kCloseWait == state_ ||
                    TcpState::kLastAck == state_;
                if (paws_state && SeqLt(opts.ts_val, ts_recent_) &&
                    kPawsMaxIdleMs > static_cast<UInt32>((now / 1000) - ts_recent_stamp_)) {
                    return;  // stale: drop (RFC 7323 s5.3 R1; s5.5 relaxes after a 24-day idle)
                }
            }

            // RFC 5961: an RST in a closing state (FIN-WAIT-1/2, CLOSING,
            // CLOSE-WAIT, LAST-ACK) is honored only when its sequence number
            // falls inside the receive window, mirroring the ESTABLISHED
            // validation below; an out-of-window RST is challenged, not
            // honored (spoofed RST protection). ESTABLISHED / SYN-SENT /
            // SYN-RCVD / TIME-WAIT handle RST in their own cases.
            if (hdr.IsRst() && TcpState::kEstablished != state_ &&
                TcpState::kSynSent != state_ && TcpState::kSynRcvd != state_ &&
                TcpState::kTimeWait != state_) {
                switch (state_) {
                case TcpState::kFinWait1:
                case TcpState::kFinWait2:
                case TcpState::kClosing:
                case TcpState::kCloseWait:
                case TcpState::kLastAck: {
                    const bool valid = (hdr.seq == rcv_nxt_) ||
                        (SeqLt(rcv_nxt_, hdr.seq) && SeqLt(hdr.seq, rcv_nxt_ + rcv_wnd_));
                    if (valid) {
                        Transition(TcpState::kClosed);
                    } else {
                        SendChallengeAck();
                    }
                    return;
                }
                default:
                    // kListen/kClosed (and any future state) must not fall into
                    // an unconditional close here - only the closing states above
                    // may Transition(kClosed) on a valid in-window RST.
                    break;
                }
            }

            switch (state_) {
            case TcpState::kSynSent: {
                // RFC 7413: the SYN+ACK may acknowledge the fast-open early
                // data too (ack in [iss+1, snd_nxt_]); reject only out-of-range.
                if (hdr.IsAck() &&
                    (SeqLt(hdr.ack, iss_ + 1) || SeqLt(snd_nxt_, hdr.ack))) {
                    // Bad ACK on SYN+ACK: RFC 5961 style rejection. An RST
                    // carrying an out-of-range ACK is dropped too - it never
                    // legitimately acknowledges our SYN (RFC 5961 s5.2:
                    // acceptable ACK must lie in [iss+1, snd_nxt_]), and
                    // accepting it would let any spoofed RST kill the
                    // handshake at zero guessing cost.
                    return;
                }
                // RFC 5961 s5.2: an RST in SYN-SENT closes the connection
                // only when it carries an acceptable ACK (acknowledging the
                // SYN, i.e. ack in [iss+1, snd_nxt_]; the range covers TFO,
                // where the SYN+ACK may acknowledge the fast-open early data
                // as well - ack == snd_nxt_ is legitimate there). A bare RST
                // (no ACK flag) or an RST with an out-of-range ACK must be
                // dropped - accepting it would let any spoofed RST kill the
                // handshake at zero guessing cost.
                if (hdr.IsRst()) {
                    if (hdr.IsAck() && !SeqLt(hdr.ack, iss_ + 1) && !SeqLt(snd_nxt_, hdr.ack)) {
                        Transition(TcpState::kClosed);
                    }
                    return;
                }
                if (hdr.IsSyn()) {
                    irs_ = hdr.seq;
                    rcv_nxt_ = irs_ + 1;
                    // RFC 7323: apply the peer's window scale.
                    TcpOpts opts_this;
                    if (ParseTcpOpts(data, len, hdr.hdr_len, opts_this)) {
                        if (opts_this.has_wscale) {
                            snd_wscale_ = opts_this.wscale;
                        }
                        // Both-sides rule: our advertised window scales only
                        // when the peer answered our WSOPT offer.
                        rcv_wscale_ = opts_this.has_wscale ? kWindowScaleOffer : 0;
                        if (opts_this.has_mss) {
                            SetPeerMss(opts_this.mss);
                        } else {
                            // RFC 1122 s4.2.2.6: the peer's SYN+ACK carried no
                            // MSS option - default to 536-byte segments.
                            SetPeerMss(536);
                        }
                        // RFC 2018: the peer advertised SACK-permitted on its
                        // SYN+ACK - we may send SACK blocks on this connection.
                        // Both sides must have offered: if WE suppressed
                        // SACK-permitted (kTcpNoSackPermitted) the connection
                        // is SACK-less even if the peer offered it.
                        if (opts.has_sack) {
                            peer_syn_sack_ = true;
                            sack_ok_ = !no_sack_permitted_;
                        }
                        // RFC 7323: both SYNs must have carried the TSopt for
                        // the option to be active - the peer's answer alone
                        // does not activate it when we suppressed the offer
                        // (TS disabled, MD5 option space, TFO fast-open SYN).
                        timestamps_ok_ = opts.has_timestamp && syn_ts_offered_;
                        // RFC 7323 s4.2: TsRecent anchors at the SYN+ACK's
                        // TSval. Without this a peer whose millisecond clock
                        // is near the 2^32 wrap (a ~49-day uptime) would have
                        // its FIRST data segment compared against the initial
                        // zero anchor and wrongly dropped as stale - the
                        // PAWS check would stall the connection forever.
                        if (opts.has_timestamp) {
                            ts_recent_ = opts.ts_val;
                            ts_recent_stamp_ = static_cast<UInt32>((now / 1000) & 0xFFFFFFFF);
                        }
                        // RFC 7413: remember the peer's TFO cookie for a
                        // future fast-open SYN.
                        if (opts.has_tfo) {
                            SetTfoCookie(opts.tfo_cookie);
                        }
                    } else {
                        // RFC 1122 s4.2.2.6: a malformed option stream
                        // (truncated length byte, option overrun) yields no
                        // usable negotiation - behave exactly as if no
                        // options were present: 536-byte segments, no window
                        // scaling, no SACK, no TFO. (Failing to do so would
                        // leave the constructor default 1460 in place while
                        // an absent option correctly forces 536 - the same
                        // wire condition, two different states.)
                        SetPeerMss(536);
                    }
                    snd_wnd_ = static_cast<UInt32>(hdr.window) << snd_wscale_;
                    // Kernel tcp_rcv_synsent (tcp_input_66.c:6409):
                    //   tp->max_window = tp->snd_wnd;
                    // an ASSIGNMENT at the handshake (later updates only grow
                    // it, tcp_input_66.c:3596-3597).
                    max_window_ = snd_wnd_;
                    snd_wl1_ = hdr.ack;  // RFC 793: window update anchor
                    snd_wl2_ = hdr.seq;
                    cc_.snd_wnd = snd_wnd_;
                    // ECN: negotiated when both ends offered ECE.
                    ecn_active_ = ecn_requested_ && hdr.IsEce();
                    if (hdr.IsAck()) {
                        // Handshake completed: the peer is alive - anchor the
                        // keepalive idle clock here, or last_rx_ stays 0 and
                        // OnPoll fires a spurious probe immediately (B1 moved
                        // the refresh out of the OnSegment prologue).
                        last_rx_ = now;
                        keepalive_probes_ = 0;
                        SendSegment(iss_ + 1, rcv_nxt_, kFlagAck | (ecn_active_ ? kFlagEce : 0), NULLPTR, 0);
                        Transition(TcpState::kEstablished);
                        syn_retry_count_ = 0;  // handshake completed: clear the SYN budget
                        rto_deadline_ = 0;  // the SYN+ACK retransmit timer is done
                        // RFC 7413 5.2: a SYN+ACK that acknowledges only the
                        // SYN (the server refused the fast-open early data -
                        // syncookie mode, rotated secret, expired cookie) leaves
                        // the early bytes stranded: SendSynWithData delivered
                        // them inline (never in retrans_queue_), so the unacked
                        // prefix would sit in [snd_una_, snd_nxt_) with no timer
                        // and no queue entry - silently lost. Re-queue the
                        // unacked bytes from tfo_syn_data_ and resend them now
                        // so they retransmit like any other data.
                        if (SeqLt(hdr.ack, snd_nxt_) && !tfo_syn_data_.empty()) {
                            const UInt32 off = hdr.ack - (iss_ + 1);
                            const UInt32 n = snd_nxt_ - hdr.ack;
                            buf::BufRef pkt = BuildSegmentPacket(
                                local_, remote_, hdr.ack, rcv_nxt_,
                                kFlagAck | kFlagPsh,
                                tfo_syn_data_.data() + off, n,
                                AdvertisedWindow(), rcv_wscale_,
                                Md5Key(), Md5KeyLen(), NULLPTR, 0, NULLPTR, ecn_active_);
                            if (!pkt.IsEmpty()) {
                                SentSeg seg;
                                seg.seq = hdr.ack;
                                seg.len = n;
                                seg.sent_at = now;
                                seg.rto = 0;
                                seg.sent_delivered = cc_.delivered;
                                seg.sent_delivered_pkts = cc_.delivered_pkts;
                                seg.pkt_count = PktCount(seg.len, peer_mss_);
                                seg.app_limited = (0 != cc_.app_limited) ? 1 : 0;
                                seg.is_retrans = 1;  // early data already sent in the SYN
                                seg.data = std::move(pkt);
                                // Reentrancy (D12 order): the segment MUST enter
                                // retrans_queue_ BEFORE the sink emits it. A
                                // synchronous backend delivers the peer's ACK
                                // reentrantly INSIDE sink_(); with the queue
                                // still missing this segment that ACK would be
                                // processed against the old snd_una_ and the
                                // segment pushed afterwards would never be
                                // reaped (its ACK already came), leaving the
                                // RTO to retransmit ACKed data. The kernel
                                // equivalent (tcp_connect_queue_skb) also
                                // queues the skb before transmitting it.
                                if (sink_) {
                                    // Kernel tcp_event_data_sent runs INSIDE
                                    // __tcp_transmit_skb, before retrans_out is
                                    // incremented: snapshot the gate first.
                                    const bool pipe_empty = (0 == PipeInFlightBytes());
                                    // Account BEFORE the move: push_front moves `seg`.
                                    PipeAccountSeg(seg, +1);
                                    retrans_queue_.push_front(std::move(seg));
                                    NotifyTxStart(pipe_empty);
                                    // Kernel TCPCB_SACKED_RETRANS accounting:
                                    // the requeued early data is retransmitted.
                                    // The pipe sum already counted it: seg has
                                    // is_retrans set BEFORE the push, so
                                    // PipeAccountSeg(seg, +1) included it.
                                    retrans_out_pkts_ += retrans_queue_.front().pkt_count;
                                    // Kernel tcp_output_66.c:3390-3392: this
                                    // re-send is a real retransmission, so it
                                    // increments undo_retrans too.
                                    if (undo_retrans_ < 0) {
                                        undo_retrans_ = 0;
                                    }
                                    undo_retrans_ += static_cast<Int32>(
                                        retrans_queue_.front().pkt_count);
                                    sink_(retrans_queue_.front().data.Clone());  // retransmit now
                                    // This re-send IS a data retransmission
                                    // (the early bytes were already sent in the
                                    // SYN): count it, mirroring RetransmitFront
                                    // and RetransmitEarliestMissing.
                                    ++retransmit_count_;
                                    // Kernel tcp_retransmit_skb
                                    // (tcp_output_66.c:3325): tp->total_retrans
                                    // += tcp_skb_pcount(skb).
                                    total_retrans_pkts_ +=
                                        retrans_queue_.front().pkt_count;
                                } else {
                                    // Account BEFORE the move (see above).
                                    PipeAccountSeg(seg, +1);
                                    retrans_queue_.push_front(std::move(seg));
                                }
                                ArmRetransmit(now);
                            }
                        }
                        FlushPendingSend(now);
                    } else {
                        // Simultaneous open: reply SYN+ACK.
                        SendSegment(iss_, rcv_nxt_, kFlagSyn | kFlagAck | (ecn_requested_ ? kFlagEce : 0), NULLPTR, 0);
                        Transition(TcpState::kSynRcvd);
                    }
                }
                break;
            }
            case TcpState::kSynRcvd: {
                if (hdr.IsRst()) {
                    // RFC 5961: validate the RST sequence number within the
                    // receive window before honoring it; otherwise challenge
                    // (mirror of the Established branch). A spoofed RST with
                    // a random seq is dropped with a challenge instead of
                    // killing the half-open connection.
                    const bool valid = (hdr.seq == rcv_nxt_) ||
                        (SeqLt(rcv_nxt_, hdr.seq) && SeqLt(hdr.seq, rcv_nxt_ + rcv_wnd_));
                    if (valid) {
                        Transition(TcpState::kClosed);
                    } else {
                        SendChallengeAck();
                    }
                    break;
                }
                if (hdr.IsSyn() && !hdr.IsAck()) {
                    // Duplicate SYN (RFC 793 retransmission or a TCP Fast Open
                    // re-send after a plain SYN). Accept data that starts at
                    // rcv_nxt (peer seq X+1) ONLY when the SYN carries a valid
                    // TFO cookie within the early-data cap - mirror of the
                    // first-SYN gate (stack.cpp OnPacket). A cookie-less or
                    // stale-cookie re-send (the server already refused the
                    // early data on the first SYN) must not bypass the
                    // verification (spoof vector) or the 16 KB cap. Invalid
                    // cookie: drop the payload; the SYN+ACK retransmit timer
                    // still answers the SYN.
                    if (payload_len > 0 && hdr.seq == (rcv_nxt_ - 1)) {
                    TcpOpts opts_this;
                    const bool tfo_gate =
                        payload_len <= kTfoMaxEarlyData &&
                        ParseTcpOpts(data, len, hdr.hdr_len, opts_this) &&
                        opts_this.has_tfo && VerifyTfoCookie(opts_this.tfo_cookie);
                        // The SYN occupies seq X; payload maps to seq X+1 == rcv_nxt.
                        if (tfo_gate && recv_cb_) {
                            const UInt32 prev = rcv_nxt_;
                            rcv_nxt_ += payload_len;  // advance before callback
                            if (!recv_cb_(payload, payload_len)) {
                                rcv_nxt_ = prev;  // backpressure rollback
                            rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                            }
                        }
                    }
                    if (hdr.seq == irs_) {
                        // Duplicate SYN (RFC 793 s3.9): the peer retransmitted
                        // its original SYN because our SYN+ACK was lost. Re-send
                        // the SYN+ACK so the handshake survives without waiting
                        // for the RTO timer - mirror of Linux
                        // tcp_rcv_state_process, which answers a seq-matching
                        // duplicate SYN in SYN_RECV with a fresh SYN+ACK. Runs
                        // after the TFO early-data handling above, so a
                        // duplicate SYN+data still gets its payload processed
                        // first.
                        SendSynAck();
                    }
                    break;
                }
                if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                    snd_wnd_ = static_cast<UInt32>(hdr.window) << snd_wscale_;
                    // Kernel tcp_rcv_synsent: tp->max_window = tp->snd_wnd.
                    max_window_ = snd_wnd_;
                    snd_wl1_ = hdr.ack;
                    snd_wl2_ = hdr.seq;
                    cc_.snd_wnd = snd_wnd_;
                    // ECN: activated at negotiation time (our SYN+ACK already
                    // answered the client's ECE+CWR offer - RFC 3168 s6.1.1).
                    // The client's handshake-completing ACK does NOT reliably
                    // carry ECE (Linux never sets it there), so requiring it
                    // would strand ECN on every real Linux client.
                    ecn_active_ = ecn_requested_;
                    // RFC 2018: the client advertised SACK-permitted on its SYN
                    // (we answered with SACK-permitted too) - we may send SACK
                    // blocks on this connection. Both sides must have offered:
                    // if WE suppressed SACK-permitted (kTcpNoSackPermitted) the
                    // connection is SACK-less even if the peer offered it.
                    {
                    TcpOpts opts_this;
                    if (ParseTcpOpts(data, len, hdr.hdr_len, opts_this) && opts_this.has_sack) {
                        peer_syn_sack_ = true;
                        sack_ok_ = !no_sack_permitted_;
                    }
                    }
                    // RFC 7323: the client offered timestamps on its SYN and
                    // our SYN+ACK answered - the option is active (both sides
                    // must carry the TSopt).
                    timestamps_ok_ = peer_ts_offered_ && syn_ts_offered_;
                    // RFC 7323 s4.2: TsRecent anchors at the handshake - the
                    // client's SYN carried the first TSval of the exchange
                    // (recorded as peer_ts_offered_); the completing ACK's own
                    // TSval (when present) anchors the PAWS clock here so a
                    // near-2^32-wrap clock is not compared against a zero
                    // anchor.
                    if (peer_ts_offered_) {
                        TcpOpts ts_anchor;
                        if (ParseTcpOpts(data, len, hdr.hdr_len, ts_anchor) && ts_anchor.has_timestamp) {
                            ts_recent_ = ts_anchor.ts_val;
                            ts_recent_stamp_ = static_cast<UInt32>((now / 1000) & 0xFFFFFFFF);
                        }
                    }
                    // Handshake completed: anchor the keepalive idle clock
                    // (last_rx_ must not stay 0 - OnPoll would fire a
                    // spurious probe; see the SynSent branch).
                    last_rx_ = now;
                    keepalive_probes_ = 0;
                    Transition(TcpState::kEstablished);
                    syn_retry_count_ = 0;  // handshake completed: clear the SYN budget
                    rto_deadline_ = 0;  // the SYN+ACK retransmit timer is done
                    FlushPendingSend(now);
                    // The peer may piggyback the first data segment on the
                    // ACK that completes the handshake (common in fast stacks).
                    if (payload_len > 0 && hdr.seq == rcv_nxt_) {
                        const UInt32 prev = rcv_nxt_;
                        rcv_nxt_ += payload_len;  // advance before callback (piggyback ACK)
                        if (recv_cb_ && !recv_cb_(payload, payload_len)) {
                            rcv_nxt_ = prev;  // backpressure: don't consume or ACK the data
                            rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                            break;
                        }
                        if (rcv_blocked_) {
                            ArmWindowUpdateAck(now);  // window reopens (RFC 1122 s4.2.3.4)
                        }
                        rcv_blocked_ = false;  // accepted: the receive window is open
                        if (quickack_) {
                            // TCP_QUICKACK one-shot: the handshake piggyback
                            // ACK also consumes the flag (mirror of the
                            // Established quickack path) - otherwise the next
                            // in-order segment would get a second immediate
                            // ACK after the user asked for only one.
                            SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                            quickack_ = false;
                            ack_pending_ = false;
                            ack_count_ = 0;
                            ack_deadline_ = 0;
                        } else {
                            ack_pending_ = true;
                            ack_count_ = 1;
                            if (0 == ack_deadline_) {
                                ack_deadline_ = now + kDelayedAckMs * 1000;
                                timers_dirty_.store(true, std::memory_order_relaxed);
                            }
                        }
                    }
                }
                break;
            }
            case TcpState::kEstablished: {
                if (hdr.IsRst()) {
                    // RFC 5961: validate the RST sequence number within the
                    // receive window before honoring it; otherwise challenge.
                    const bool valid = (hdr.seq == rcv_nxt_) ||
                        (SeqLt(rcv_nxt_, hdr.seq) && SeqLt(hdr.seq, rcv_nxt_ + rcv_wnd_));
                    if (valid) {
                        Transition(TcpState::kClosed);
                    } else {
                        SendChallengeAck();
                    }
                    break;
                }
                if (hdr.IsSyn()) {
                    // RFC 5961: ignore unexpected SYN in Established, EXCEPT a
                    // duplicate SYN+ACK whose final ACK was lost - re-ACK it so
                    // the peer stops RTOing its SYN+ACK (mirror of Linux's
                    // duplicate SYN+ACK re-ACK). Re-ACK only when the segment's
                    // ACK is legitimate ([snd_una_, snd_nxt_]); a bare SYN or an
                    // out-of-range ACK stays ignored per RFC 5961.
                    if (hdr.IsAck() && !SeqLt(hdr.ack, snd_una_) &&
                        !SeqLt(snd_nxt_, hdr.ack)) {
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                    }
                    break;
                }
                // B1: keepalive refresh - only a segment that passed the
                // seq/ack validation above (valid ACK or in-order data/FIN)
                // resets the probe counter. Junk segments (spoofed ACK beyond
                // snd_nxt_, unexpected SYN, invalid RST, out-of-window old
                // data) keep the idle clock running so the keepalive/abort
                // logic still fires against a half-dead peer.
                if ((hdr.IsAck() && !SeqLt(snd_nxt_, hdr.ack)) ||
                    (hdr.seq == rcv_nxt_ && (0 < payload_len || hdr.IsFin()))) {
                    last_rx_ = now;
                    keepalive_probes_ = 0;
                }
                const UInt32 seg_end = hdr.seq + payload_len + (hdr.IsFin() ? 1 : 0);
                if (hdr.IsAck()) {
                    // RFC 793 SND.WL: apply the peer's window only from a
                    // segment newer than the last window update - a stale or
                    // spoofed ACK must not shrink our send window to 0. The
                    // SND.WL guards alone are insufficient: an ACK beyond
                    // snd_nxt_ is rejected by OnAckReceived (line 2043), but
                    // this window update runs BEFORE it, so a spoofed
                    // out-of-range ACK with window=0 would still clamp the
                    // window to 0 and advance snd_wl1_ past every future
                    // legitimate ACK - a sticky zero-window deadlock. Gate
                    // the update on ack validity (RFC 793: window applies
                    // only to acked/valid segments; Linux tcp_ack similarly
                    // discards out-of-window ACKs).
                    if (!SeqLt(snd_nxt_, hdr.ack) &&
                        (SeqLt(snd_wl1_, hdr.ack) ||
                         (snd_wl1_ == hdr.ack && !SeqLt(hdr.seq, snd_wl2_)))) {
                        snd_wnd_ = static_cast<UInt32>(hdr.window) << snd_wscale_;
                        if (snd_wnd_ > max_window_) { max_window_ = snd_wnd_; }
                        snd_wl1_ = hdr.ack;
                        snd_wl2_ = hdr.seq;
                        cc_.snd_wnd = snd_wnd_;
                        // RFC 1122 zero-window probing: this ACK path is the
                        // ONLY place that can learn the window closed while
                        // data is already in flight (SendData/Close arm persist
                        // only on their own sends). A window-update ACK that
                        // shrinks snd_wnd_ to 0 with unacked/buffered data left
                        // must arm the persist timer, or a subsequent lost
                        // window-update ACK would deadlock the flow forever
                        // (no probe, RTO only re-arms). Mirror the SendData
                        // arming pattern.
                        if (0 == snd_wnd_ &&
                            (0 < retrans_queue_.size() || 0 < pending_send_.size()) &&
                            (0 == persist_deadline_ || now < persist_deadline_)) {
                            persist_deadline_ = now + persist_interval_;
                            timers_dirty_.store(true, std::memory_order_relaxed);
                        }
                    }
                    // RFC 5681 s2 / Linux FLAG_DATA: a segment that carries
                    // data or SYN/FIN is not a duplicate ACK even when
                    // ack == snd_una_. On a bidirectional flow the peer's data
                    // burst repeats the same cumulative ACK on every segment;
                    // counting those as dupacks triggers spurious fast
                    // retransmits and collapses cwnd. A window change alone is
                    // deliberately NOT excluded: xtcp's own receiver shrinks
                    // the advertised window per buffered out-of-order segment,
                    // so its genuine dupacks carry differing windows.
                    ack_not_dup_ = 0 < payload_len || hdr.IsFin() || hdr.IsSyn();
                    OnAckReceived(hdr.ack, hdr.IsEce(), now, &opts);  // shared parse from the OnSegment prologue (SACK blocks drive recovery)
                    ack_not_dup_ = false;
                }
                if (payload_len > 0 || hdr.IsFin()) {
                    if (hdr.seq == rcv_nxt_) {
                        // RFC 7323: TsRecent = the TSval of the accepted
                        // in-order segment (the PAWS anchor + the tsecr
                        // source for our ACKs).
                        if (timestamps_ok_ && opts_parsed && opts.has_timestamp) {
                            ts_recent_ = opts.ts_val;
                            ts_recent_stamp_ = static_cast<UInt32>((now / 1000) & 0xFFFFFFFF);
                        }
                        // RFC 793 urgent data (SO_OOBINLINE): the URG flag
                        // marks the segment - the app is notified once, the
                        // urgent bytes ride the normal stream.
                        if (hdr.IsUrg() && urgent_cb_) {
                            urgent_cb_();
                        }
                        // In-order data: deliver, then drain the out-of-order
                        // buffer for any contiguous follow-on segments.
                        // RFC 793: advance RCV.NXT BEFORE the app callback so
                        // a send the app makes inside it (echo/reply) carries
                        // an ACK that covers the just-delivered bytes. The old
                        // order (callback, then advance) made the piggyback
                        // ACK stale by one segment - with Nagle on the peer
                        // that gated one chunk per delayed-ACK (40ms) round
                        // (the interop_latency regression).
                        const UInt32 prev_rcv = rcv_nxt_;
                        rcv_nxt_ = seg_end;
                        if (0 < payload_len && recv_cb_ && !recv_cb_(payload, payload_len)) {
                            // Backpressure (Bug B): the app could not accept
                            // the data (e.g. the MIMT rx queue is full). Roll
                            // RCV.NXT back and do not ACK - otherwise the peer
                            // believes the bytes were delivered while the
                            // application silently lost them. The peer RTOs
                            // and retransmits instead. Advertise window 0
                            // (RFC 1122 s4.2.3.4) so the peer persists instead
                            // of retransmitting into an unusable window.
                            rcv_nxt_ = prev_rcv;
                            rcv_blocked_ = true;
                            ArmWindowUpdateAck(now);  // advertise window 0 NOW (RFC 1122 s4.2.3.4)
                            break;
                        }
                        if (rcv_blocked_) {
                            ArmWindowUpdateAck(now);  // window reopens (RFC 1122 s4.2.3.4)
                        }
                        rcv_blocked_ = false;  // accepted: the receive window is open
                        if (TcpState::kEstablished != state_) {
                            // The recv handler closed or aborted this connection
                            // reentrantly - do not keep driving the state machine
                            // (a later Transition would resurrect/regress it).
                            break;
                        }
                        while (!ooo_.empty()) {
                            TrimOooToFrontier();
                            // Exact-key lookup: sequence wraparound makes
                            // std::less<UInt32> ordering meaningless at the
                            // 2^32 boundary, so do not rely on map order.
                            auto it = ooo_.find(rcv_nxt_);
                            if (it == ooo_.end()) {
                                break;
                            }
                            const OutSeg& seg = it->second;
                            const UInt32 prev_drain = rcv_nxt_;
                            rcv_nxt_ += static_cast<UInt32>(seg.data.size());  // advance before callback (piggyback ACK)
                            // RFC 7323: the drained segment is now in-order -
                            // its TSval advances TsRecent (the PAWS anchor),
                            // mirroring the closing-state drain path.
                            if (0 != seg.ts_val) {
                                ts_recent_ = seg.ts_val;
                                ts_recent_stamp_ = static_cast<UInt32>((now / 1000) & 0xFFFFFFFF);
                            }
                            if (!seg.data.empty() && recv_cb_ && !recv_cb_(seg.data.data(), static_cast<UInt32>(seg.data.size()))) {
                                // Backpressure: drop this buffered segment
                                // (refund its bytes) and stop draining; the
                                // peer retransmits, keeping the data intact
                                // end-to-end.
                                rcv_nxt_ = prev_drain;  // rollback
                                rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                                ArmWindowUpdateAck(now);
                                ooo_bytes_ -= static_cast<UInt32>(seg.data.size());
                                ooo_.erase(it);
                                break;
                            }
                            if (TcpState::kEstablished != state_) {
                                // The recv handler closed or aborted this
                                // connection reentrantly - stop draining and
                                // exit OnSegment (a later Transition would
                                // resurrect/regress the closed connection).
                                return;
                            }
                            ooo_bytes_ -= static_cast<UInt32>(seg.data.size());
                            const bool fin = seg.fin;  // capture before erase (seg aliases the node)
                            ooo_.erase(it);
                            if (fin) {
                                // RFC 793: an out-of-order FIN is consumed once
                                // its data fills the gap - enter CLOSE-WAIT.
                                ++rcv_nxt_;
                                SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                                Transition(TcpState::kCloseWait);
                                NotifyStateChanged();  // peer half-closed: the app must see it
                                break;
                            }
                        }
                        if (hdr.IsFin()) {
                            SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                            Transition(TcpState::kCloseWait);
                            NotifyStateChanged();  // peer half-closed: the app must see it
                        } else if (quickack_) {
                            // TCP_QUICKACK: ACK every segment immediately.
                            // Linux one-shot semantics: the flag is cleared by
                            // the first ACK, so re-enable via SetOption each
                            // time immediate ACKs are wanted again.
                            SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                            quickack_ = false;
                            ack_pending_ = false;
                            ack_count_ = 0;
                            ack_deadline_ = 0;
                        } else {
                            ack_pending_ = true;
                            ++ack_count_;
                            // Linux __tcp_ack_snd_check: ACK at once when
                            // more than one full-sized segment (rcv_mss) is
                            // unacknowledged - BYTES, not segment count. A
                            // GRO/LRO super-segment covering several MSS
                            // arrives as ONE segment and must not wait for
                            // the 40 ms delayed-ACK timer. rcv_mss is bounded
                            // by our advertised MSS (kAdvertisedMss, the SYN
                            // MSS option), so "payload > advertised MSS"
                            // implies "more than one full-sized segment".
                            if (2 <= ack_count_ || payload_len > kAdvertisedMss) { SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                                ack_pending_ = false;
                                ack_count_ = 0;
                                ack_deadline_ = 0;
                            } else if (0 == ack_deadline_) {
                                ack_deadline_ = now + kDelayedAckMs * 1000;
                            timers_dirty_.store(true, std::memory_order_relaxed);
                            }
                        }
                    } else if (SeqLt(hdr.seq, rcv_nxt_)) {
                        // Fully or partially old data: re-ACK. A partially
                        // overlapping segment (hdr.seq < rcv_nxt_ < seg_end)
                        // must not be dropped whole - its fresh suffix
                        // [rcv_nxt_, seg_end) starts exactly at the receive
                        // frontier, so deliver it in place (the peer may have
                        // resent a segment whose head overlaps already-SACKed
                        // bytes) and drain any now-contiguous out-of-order
                        // buffer. Only a fully-old segment is discarded.
                        if (!SeqLt(rcv_nxt_, seg_end)) {
                            // RFC 2883 D-SACK: a fully-old segment is a
                            // duplicate (a spurious retransmission or a
                            // reordered original) - record its range so the
                            // next ACK's FIRST SACK block advertises it.
                            dsack_left_ = hdr.seq;
                            dsack_right_ = seg_end;
                            dsack_pending_ = true;
                        }
                        if (SeqLt(rcv_nxt_, seg_end)) {
                            const UInt32 trim_off = rcv_nxt_ - hdr.seq;
                            const UInt32 fresh = payload_len - trim_off;
                            // Advance before the callback (piggyback ACK must
                            // cover the delivered bytes - see the in-order
                            // path above); roll back on backpressure.
                            const UInt32 prev_trim = rcv_nxt_;
                            rcv_nxt_ = hdr.seq + payload_len;
                            if (0 == fresh || !recv_cb_ || recv_cb_(payload + trim_off, fresh)) {
                                // Fresh suffix delivered (or backpressure-free):
                                // the frontier already advanced past the
                                // segment's data.
                                if (TcpState::kEstablished != state_) {
                                    // The recv handler closed or aborted this
                                    // connection reentrantly - stop (a later
                                    // Transition would resurrect/regress it).
                                    break;
                                }
                                if (hdr.IsFin()) {
                                    // The FIN sits at the frontier (fresh when a
                                    // partial overlap reaches it): consume it.
                                    ++rcv_nxt_;
                                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                                    Transition(TcpState::kCloseWait);
                                    break;
                                }
                                while (!ooo_.empty()) {
                                    TrimOooToFrontier();
                                    // Exact-key lookup: sequence wraparound makes
                                    // std::less<UInt32> ordering meaningless at
                                    // the 2^32 boundary, so do not rely on map order.
                                    auto it = ooo_.find(rcv_nxt_);
                                    if (it == ooo_.end()) {
                                        break;
                                    }
                                    const OutSeg& os = it->second;
                                    const UInt32 prev_os = rcv_nxt_;
                                    rcv_nxt_ += static_cast<UInt32>(os.data.size());  // advance before callback
                                    if (!os.data.empty() && recv_cb_ && !recv_cb_(os.data.data(), static_cast<UInt32>(os.data.size()))) {
                                        // Backpressure: drop and stop draining.
                                        rcv_nxt_ = prev_os;  // rollback
                                        rcv_blocked_ = true;  // advertise window 0 (RFC 1122 s4.2.3.4)
                                        ArmWindowUpdateAck(now);
                                        ooo_bytes_ -= static_cast<UInt32>(os.data.size());
                                        ooo_.erase(it);
                                        break;
                                    }
                                    if (TcpState::kEstablished != state_) {
                                        // The recv handler closed or aborted this
                                        // connection reentrantly - stop draining
                                        // and exit OnSegment (a later Transition
                                        // would resurrect/regress it).
                                        return;
                                    }
                                    ooo_bytes_ -= static_cast<UInt32>(os.data.size());
                                    const bool fin = os.fin;  // capture before erase (os aliases the node)
                                    ooo_.erase(it);
                                    if (fin) {
                                        ++rcv_nxt_;
                                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                                        Transition(TcpState::kCloseWait);
                                        break;
                                    }
                                }
                            } else {
                                // Backpressure: the fresh suffix was not
                                // consumed - roll the frontier back so the
                                // peer RTOs and retransmits it. Advertise
                                // window 0 (RFC 1122 s4.2.3.4).
                                rcv_nxt_ = prev_trim;
                                rcv_blocked_ = true;
                                ArmWindowUpdateAck(now);
                            }
                        }
                        // Re-ACK of old data: consumes the TCP_QUICKACK
                        // one-shot, but must NOT clear the delayed-ACK state:
                        // an in-order segment may have armed ack_deadline_
                        // earlier, and wiping it here would lose that ACK
                        // entirely (the peer's recovery stalls on it).
                        // RFC 5961 / Linux tcp_challenge_ack_limit: an
                        // on-path flood of old segments must NOT be reflected
                        // 1:1 into dup-ACKs - rate-limit via SendDupAck
                        // (100/s; NOT the 8/s challenge window, which would
                        // stall fast-retransmit's 3-dup-ACK burst).
                        SendDupAck();
                        quickack_ = false;
                    } else {
                        // Out-of-order: RFC 793 accepts only segments inside
                        // the receive window; window-external data must be
                        // dropped (never buffered) - otherwise an attacker
                        // fills the ooo buffer and starves real reassembly.
                        const UInt32 wnd_end = rcv_nxt_ + rcv_wnd_;
                        if (SeqLt(hdr.seq, wnd_end) || hdr.seq == wnd_end) {
                            if ((ooo_bytes_ + payload_len) <= OooCapacity(window_)) {
                                OutSeg entry;
                                entry.data.assign(payload, payload + payload_len);
                                entry.fin = hdr.IsFin();
                                // RFC 7323: anchor the drained segment's
                                // TsRecent (see the other OOO insert sites).
                                if (timestamps_ok_ && opts_parsed && opts.has_timestamp) {
                                    entry.ts_val = opts.ts_val;
                                }
                                // Same-key replacement must refund the old
                                // entry's bytes - otherwise retransmissions
                                // inflate ooo_bytes_ and starve real
                                // reassembly (kOooLimit eviction).
                                auto existing = ooo_.find(hdr.seq);
                                if (existing != ooo_.end()) {
                                    ooo_bytes_ -= static_cast<UInt32>(existing->second.data.size());
                                }
                                ooo_[hdr.seq] = std::move(entry);
                                ooo_bytes_ += payload_len;
                            }
                            // Out-of-order duplicate ACK: consumes the
                            // TCP_QUICKACK one-shot, but must NOT clear the
                            // delayed-ACK state (an in-order segment may have
                            // armed ack_deadline_ earlier; wiping it would
                            // lose that ACK and stall the peer's recovery).
                        // RFC 5961: an OOO segment flood must not reflect
                        // 1:1 into dup-ACKs - rate-limit via SendDupAck
                        // (100/s; NOT the 8/s challenge window, which would
                        // stall fast-retransmit's 3-dup-ACK burst).
                        SendDupAck();
                        quickack_ = false;
                        }
                    }
                } else if (0 == payload_len) {
                    // Pure ACK or window probe.
                    if (hdr.seq == (rcv_nxt_ - 1)) {
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);  // window probe
                    }
                }
                break;
            }
            case TcpState::kFinWait1: {
                // RFC 793: data may still arrive after our FIN (half-close);
                // process and ACK it so the peer's send path keeps flowing.
                const bool fin_consumed =
                    ProcessClosingData(payload, payload_len, hdr.seq, hdr.IsFin(), now,
                                       (timestamps_ok_ && opts_parsed && opts.has_timestamp) ? opts.ts_val : 0);
                if (TcpState::kClosed == state_) {
                    // The recv handler aborted (or closed) this connection
                    // reentrantly inside ProcessClosingData's recv_cb_ - do
                    // not keep driving the state machine (a later FIN/ACK
                    // Transition would resurrect kClosed into a closing
                    // state and strand the connection for 2MSL).
                    break;
                }
                if (hdr.IsAck()) {
                    // RFC 793 SND.WL: apply the peer's window from segments
                    // newer than the last window update (mirror of the
                    // Established path). FinWait1/2 still transmit until the
                    // peer ACKs the FIN, so a stale or spoofed ACK must not
                    // shrink snd_wnd_ to 0 and strand the final retransmits.
                    if (!SeqLt(snd_nxt_, hdr.ack) &&
                        (SeqLt(snd_wl1_, hdr.ack) ||
                         (snd_wl1_ == hdr.ack && !SeqLt(hdr.seq, snd_wl2_)))) {
                        snd_wnd_ = static_cast<UInt32>(hdr.window) << snd_wscale_;
                        if (snd_wnd_ > max_window_) { max_window_ = snd_wnd_; }
                        snd_wl1_ = hdr.ack;
                        snd_wl2_ = hdr.seq;
                        cc_.snd_wnd = snd_wnd_;
                    }
                    OnAckReceived(hdr.ack, hdr.IsEce(), now, NULLPTR);
                }
                if (fin_consumed) {
                    // The peer's FIN was consumed by the closing-data path
                    // (an in-order pure FIN, or a buffered out-of-order
                    // FIN whose gap just filled). ProcessClosingData already
                    // re-ACKed it - now run the RFC 793 transition.
                    if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                        Transition(TcpState::kTimeWait);
                        EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                    } else {
                        Transition(TcpState::kClosing);
                    }
                    break;
                }
                if (hdr.IsFin()) {
                    // RFC 793: the FIN occupies the sequence number after its
                    // data. ProcessClosingData already advanced rcv_nxt_ past
                    // any in-order payload - do not rewind it to hdr.seq+1
                    // (that would re-ACK delivered bytes and cause the peer
                    // to retransmit them).
                    if (hdr.seq + payload_len == rcv_nxt_) {
                        ++rcv_nxt_;  // FIN directly after the delivered data
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                        if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                            Transition(TcpState::kTimeWait);
                            EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                        } else {
                            Transition(TcpState::kClosing);
                        }
                        break;
                    }
                    if (hdr.seq == rcv_nxt_ - 1) {
                        // duplicate/old FIN: keep the frontier.
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                        if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                            Transition(TcpState::kTimeWait);
                            EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                        } else {
                            Transition(TcpState::kClosing);
                        }
                        break;
                    }
                    // Out-of-order FIN: ProcessClosingData buffered it (or
                    // dropped it window-external). It must NOT transition
                    // yet - the FIN is consumed when the gap fills. Do NOT
                    // break: the ACK check below still advances FinWait1 ->
                    // FinWait2, so a FIN that is already fully ACKed cannot
                    // strand the connection in FinWait1 with no timers
                    // (permanent slot leak when the peer dies).
                }
                if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                    Transition(TcpState::kFinWait2);
                    finwait2_deadline_ = now + finwait2_timeout_;  // tcp_fin_timeout
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
                break;
            }
            case TcpState::kFinWait2: {
                const bool fin_consumed =
                    ProcessClosingData(payload, payload_len, hdr.seq, hdr.IsFin(), now,
                                       (timestamps_ok_ && opts_parsed && opts.has_timestamp) ? opts.ts_val : 0);
                if (TcpState::kClosed == state_) {
                    // The recv handler aborted (or closed) this connection
                    // reentrantly inside ProcessClosingData's recv_cb_ - do
                    // not keep driving the state machine (a later FIN/ACK
                    // Transition would resurrect kClosed into a closing
                    // state and strand the connection for 2MSL).
                    break;
                }
                if (hdr.IsAck()) {
                    // RFC 793 SND.WL: apply the peer's window from segments
                    // newer than the last window update (mirror of the
                    // Established path). FinWait1/2 still transmit until the
                    // peer ACKs the FIN, so a stale or spoofed ACK must not
                    // shrink snd_wnd_ to 0 and strand the final retransmits.
                    if (!SeqLt(snd_nxt_, hdr.ack) &&
                        (SeqLt(snd_wl1_, hdr.ack) ||
                         (snd_wl1_ == hdr.ack && !SeqLt(hdr.seq, snd_wl2_)))) {
                        snd_wnd_ = static_cast<UInt32>(hdr.window) << snd_wscale_;
                        if (snd_wnd_ > max_window_) { max_window_ = snd_wnd_; }
                        snd_wl1_ = hdr.ack;
                        snd_wl2_ = hdr.seq;
                        cc_.snd_wnd = snd_wnd_;
                    }
                    OnAckReceived(hdr.ack, hdr.IsEce(), now, NULLPTR);
                }
                if (fin_consumed) {
                    // FIN consumed via the closing-data path (in-order pure
                    // FIN or gap-filled out-of-order FIN): RFC 793
                    // FinWait2 + FIN -> TIME-WAIT (2MSL).
                    Transition(TcpState::kTimeWait);
                    EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                    break;
                }
                if (hdr.IsFin()) {
                    // RFC 793: the FIN occupies the sequence number after its
                    // data; ProcessClosingData already advanced rcv_nxt_ past
                    // any in-order payload - do not rewind it.
                    if (hdr.seq + payload_len == rcv_nxt_) {
                        ++rcv_nxt_;
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                        Transition(TcpState::kTimeWait);
                        EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                    } else if (hdr.seq == rcv_nxt_ - 1) {
                        // duplicate/old FIN: keep the frontier.
                        SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                        Transition(TcpState::kTimeWait);
                        EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                    }
                    // Out-of-order FIN: ProcessClosingData buffered it; the
                    // TIME-WAIT transition runs when the gap fills (the
                    // fin_consumed branch above).
                }
                break;
            }
            case TcpState::kCloseWait:
                // RFC 793 half-close: after the peer's FIN, the local side
                // may still send data (the echo reply). Its ACKs must still
                // advance snd_una and flush buffered sends - otherwise the
                // reply is stranded at the initial cwnd.
                // RFC 793: a peer that FINed may still deliver data that was
                // in flight before the FIN - a pure retransmission, a trailing
                // out-of-order segment, or a merged data+FIN that arrived
                // split. Process it exactly like FinWait1/2 (deliver,
                // reassemble, ACK) - otherwise the peer's unACKed re-sends
                // burn kMaxDataRetries and the payload is silently dropped.
                ProcessClosingData(payload, payload_len, hdr.seq, hdr.IsFin(), now);
                if (TcpState::kClosed == state_) {
                    // The recv handler aborted (or closed) this connection
                    // reentrantly inside ProcessClosingData's recv_cb_ - do
                    // not keep driving the state machine (a later FIN/ACK
                    // Transition would resurrect kClosed into a closing
                    // state and strand the connection for 2MSL).
                    break;
                }
                // B1: keepalive no longer runs in CLOSE-WAIT (the OnPoll gate
                // is Established only), but the refresh stays as harmless
                // bookkeeping: a live peer's valid ACKs / duplicate FINs keep
                // the idle clock accurate should the state regress. Any
                // delivered/ACKed payload proves the peer alive as well.
                if ((hdr.IsAck() && !SeqLt(snd_nxt_, hdr.ack)) ||
                    (hdr.IsFin() && SeqLt(hdr.seq, rcv_nxt_)) ||
                    0 < payload_len) {
                    last_rx_ = now;
                    keepalive_probes_ = 0;
                }
                if (hdr.IsAck()) {
                    // RFC 793 SND.WL: apply the peer's window from segments
                    // newer than the last window update (mirror of the
                    // Established path). CloseWait still sends data, so a stale
                    // or spoofed ACK must not shrink snd_wnd_ to 0 and strand
                    // the remaining sends (FinWait1/LastAck never flush).
                    if (!SeqLt(snd_nxt_, hdr.ack) &&
                        (SeqLt(snd_wl1_, hdr.ack) ||
                         (snd_wl1_ == hdr.ack && !SeqLt(hdr.seq, snd_wl2_)))) {
                        snd_wnd_ = static_cast<UInt32>(hdr.window) << snd_wscale_;
                        if (snd_wnd_ > max_window_) { max_window_ = snd_wnd_; }
                        snd_wl1_ = hdr.ack;
                        snd_wl2_ = hdr.seq;
                        cc_.snd_wnd = snd_wnd_;
                    }
                    OnAckReceived(hdr.ack, hdr.IsEce(), now, NULLPTR);
                    if (0 < pending_send_.size()) {
                        FlushPendingSend(now);
                    }
                }
                // A duplicate FIN - or a FIN carrying retransmitted data
                // (the peer lost our ACK and merged data+FIN) - must be
                // re-ACKed, else the peer burns its retransmission budget
                // with exponential backoff.
                if (hdr.IsFin() && (hdr.seq == (rcv_nxt_ - 1) || SeqLt(hdr.seq, rcv_nxt_))) {
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                }
                break;
            case TcpState::kLastAck: {
                if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                    Transition(TcpState::kClosed);
                } else if (hdr.IsFin() && hdr.seq == (rcv_nxt_ - 1)) {
                    // Duplicate FIN (the peer retransmits its lost FIN until
                    // our ACK reaches it): re-ACK the frontier.
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                } else if (0 < payload_len || hdr.IsFin()) {
                    // The peer retransmits old data (or a combined data+FIN
                    // whose head overlaps already-delivered bytes): re-ACK the
                    // frontier so it stops burning kMaxDataRetries.
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                }
                break;
            }
            case TcpState::kClosing: {
                if (hdr.IsAck() && hdr.ack == snd_nxt_) {
                    Transition(TcpState::kTimeWait);
                    EnterTimeWait(now);  // RFC 793 2MSL before reclamation
                } else if (hdr.IsFin() && hdr.seq == (rcv_nxt_ - 1)) {
                    // Duplicate FIN: re-ACK so the peer stops retransmitting.
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                } else if (0 < payload_len || hdr.IsFin()) {
                    // Retransmitted old data / combined data+FIN: re-ACK.
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                }
                break;
            }
            case TcpState::kTimeWait: {
                // RFC 793: re-ACK on stray retransmissions during 2MSL.
                // RFC 1337: ignore RST entirely - never answer an RST with ACK.
                if (!hdr.IsRst() &&
                    (hdr.seq == (rcv_nxt_ - 1) || SeqLt(hdr.seq, rcv_nxt_))) {
                    SendSegment(snd_nxt_, rcv_nxt_, AckFlags(), NULLPTR, 0);
                }
                break;
            }
            case TcpState::kListen:
            case TcpState::kClosed:
            default:
                break;
            }
        }

        /* ---------------- TcpListener ---------------- */

        TcpListener::TcpListener(const Endpoint& local, UInt32 backlog, TxSink sink) noexcept
            : local_(local), backlog_(backlog), sink_(std::move(sink)) {
            next_iss_ = static_cast<UInt32>(0x10000000 | (local.port << 16));
            if (0 < backlog_) {
                syn_queue_ = new (std::nothrow) SynEntry[backlog_]();
            }
        }

        TcpListener::~TcpListener() noexcept {
            delete[] syn_queue_;
            syn_queue_ = NULLPTR;
        }

        bool TcpListener::OnSyn(const Byte* data, UInt32 len, const Endpoint& remote) noexcept {
            TcpHdr hdr;
            if (!ParseTcp(data, len, hdr) || !hdr.IsSyn() || hdr.IsAck()) {
                return false;
            }
            const UInt64 now_us = static_cast<UInt64>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            if (NULLPTR == syn_queue_) {
                return false;
            }
            // Re-answer a retransmitted SYN from a client already in the
            // queue: send its SYN+ACK again (same iss) instead of filling the
            // backlog with a duplicate entry. Without this, a lost SYN+ACK
            // leaves the client retransmitting into a queue that grows to the
            // backlog bound and rejects its eventual ACK.
            for (UInt32 i = 0; i < pending_; ++i) {
                SynEntry& entry = syn_queue_[i];
                if (entry.remote.family == remote.family && entry.remote.port == remote.port &&
                    entry.remote.addr[0] == remote.addr[0] && entry.remote.addr[1] == remote.addr[1] &&
                    entry.remote.addr[2] == remote.addr[2] && entry.remote.addr[3] == remote.addr[3]) {
                    const Byte* payload = data + hdr.payload_off;
                    const UInt32 payload_len = len - hdr.payload_off;
                    const UInt16 synack_win =
                        static_cast<UInt16>(((0 < rcv_buf_) ? rcv_buf_ : kDefaultWindow) >> 7);
                    SendSegmentPacket(local_, remote, entry.iss, hdr.seq + 1,
                                      kFlagSyn | kFlagAck, payload, payload_len, synack_win, sink_, 7);
                    entry.created_us = now_us;
                    return true;
                }
            }
            // Stale-entry expiry: a client whose SYN+ACK was never answered
            // (or never arrived) must not pin its slot forever - otherwise a
            // SYN flood of abandoned handshakes fills the backlog and rejects
            // legitimate SYNs. Reclaim entries idle past the timeout.
            constexpr UInt64 kSynEntryTimeoutUs = 30ull * 1000000ull;
            for (UInt32 i = 0; i < pending_; ++i) {
                if (now_us - syn_queue_[i].created_us > kSynEntryTimeoutUs) {
                    for (UInt32 j = i; j + 1 < pending_; ++j) {
                        syn_queue_[j] = syn_queue_[j + 1];
                    }
                    --pending_;
                    break;
                }
            }
            if (pending_ >= backlog_) {
                return false;
            }
            const UInt32 iss = next_iss_++;
            SynEntry& entry = syn_queue_[pending_];
            entry.remote = remote;
            entry.iss = iss;
            entry.created_us = now_us;

            // SYN+ACK(seq=iss, ack=irs+1). The window field advertises the
            // configured receive capacity, scaled by the offered window-scale
            // factor (7). NOTE: this test-only listener class always offers
            // WSOPT=7 and scales unconditionally - it does not implement the
            // conn-based both-sides WSOPT negotiation (a client that offers no
            // WSOPT gets a scaled window it may misread; acceptable for the
            // test harness it serves).
            const Byte* payload = data + hdr.payload_off;
            const UInt32 payload_len = len - hdr.payload_off;
            const UInt16 synack_win = static_cast<UInt16>(((0 < rcv_buf_) ? rcv_buf_ : kDefaultWindow) >> 7);
            SendSegmentPacket(local_, remote, iss, hdr.seq + 1, kFlagSyn | kFlagAck, payload, payload_len,
                              synack_win, sink_, 7);
            ++pending_;
            return true;
        }

        void TcpListener::OnSynAck(const Byte* data, UInt32 len, const Endpoint& remote) noexcept {
            TcpHdr hdr;
            if (!ParseTcp(data, len, hdr) || !hdr.IsAck()) {
                return;
            }
            for (UInt32 i = 0; i < pending_; ++i) {
                SynEntry& entry = syn_queue_[i];
                if (entry.remote.addr[0] == remote.addr[0] &&
                    entry.remote.port == remote.port &&
                    hdr.ack == (entry.iss + 1)) {
                    // Shift the queue (simple removal).
                    for (UInt32 j = i; j + 1 < pending_; ++j) {
                        syn_queue_[j] = syn_queue_[j + 1];
                    }
                    --pending_;
                    break;
                }
            }
        }
    }
}
