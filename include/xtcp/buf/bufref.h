#pragma once

/**
 * @file bufref.h
 * @brief Zero-copy reference-counted packet buffer with tiered pools.
 *
 * A BufRef is movable but not copyable: transfer moves the reference
 * without copying payload bytes. Ref/Unref are atomic so references can
 * cross shard boundaries; payload is never moved.
 */

#include <xtcp/stdafx.h>

#include <atomic>
#include <mutex>
#include <memory>

namespace xtcp {
    namespace buf {
        /**
         * @brief Bytes per block header (pool* + refcount). The payload
         *        returned by BufPool::Acquire() starts kHeaderBytes past the
         *        block start, so usable payload per block is
         *        BlockSize() - kHeaderBytes.
         */
        constexpr UInt32 kHeaderBytes = 16;
        /**
         * @brief Largest usable payload a single pool block can hold (the
         *        biggest size class minus the block header). Super-segments
         *        larger than this cannot be zero-copy and fall back to
         *        segmentation.
         */
        constexpr UInt32 kMaxPoolPayload = 32768 - kHeaderBytes;
        /**
         * @brief GSO segment metadata attached to a super-segment.
         */
        struct SegMeta {
            UInt32 gso_size = 0;  /**< Bytes per GSO segment */
            UInt16 mss      = 0;  /**< TCP MSS */
            UInt16 segs     = 0;  /**< Segment count */
        };

        /**
         * @brief A single tier of the buffer pool (fixed block size).
         * @note Acquire/Release are thread-safe: the per-thread cache layer
         *       is lock-free; the shared free list is mutex-serialized (not
         *       an atomic lock-free structure). Blocks cross shards via
         *       refcount handoff and return to the pool on the consumer side.
         */
        class BufPool {
        public:
            BufPool(UInt32 block_size, UInt32 block_count) noexcept;
            virtual ~BufPool() noexcept;
            /**
             * @brief Allocates a block with refcount header.
             * @return Payload pointer or NULLPTR when exhausted.
             */
            Byte* Acquire() noexcept;
            /**
             * @brief Returns a block to the pool (refcount must be zero).
             * @param payload Payload pointer from Acquire().
             */
            void Release(Byte* payload) noexcept;
            /**
             * @brief Bytes of usable payload per block.
             */
            UInt32 BlockSize() const noexcept { return block_size_; }
            /**
             * @brief Total blocks in this tier.
             */
            UInt32 Capacity() const noexcept { return block_count_; }
            /**
             * @brief Free blocks remaining.
             */
            UInt32 FreeCount() const noexcept { return free_count_.load(std::memory_order_relaxed); }
            /**
             * @brief True after ShutdownPools: no further Acquire/Release
             *        writes into this pool are allowed.
             */
            bool IsDestroyed() const noexcept { return destroyed_.load(std::memory_order_acquire); }
            /**
             * @brief Marks the pool destroyed (only ShutdownPools).
             */
            void MarkDestroyed() noexcept { destroyed_.store(true, std::memory_order_release); }
            /**
             * @brief Re-arms a destroyed pool for reuse (only InitPools after
             *        ShutdownPools; the arena is still allocated).
             */
            void ResetDestroyed() noexcept { destroyed_.store(false, std::memory_order_release); }
            /**
             * @brief Returns a batch of blocks to the global free list.
             * @param payloads Block payloads to return.
             * @param count Number of blocks.
             */
            void FlushToGlobal(Byte* const* payloads, UInt32 count) noexcept;
            /**
             * @brief Creates a heap-overflow owner for one tier. It has no
             *        arena: BufRef::Acquire hands out individually heap-
             *        allocated blocks tagged with this owner when the tier's
             *        arena is empty, and Release frees them.
             */
            static BufPool* NewHeapOverflow(UInt32 block_size) noexcept;
            /**
             * @brief True for a heap-overflow owner (see NewHeapOverflow).
             */
            bool IsHeapOverflow() const noexcept { return heap_overflow_; }

        private:
            Byte*                   arena_       = NULLPTR;
            bool                    heap_overflow_ = false;  /**< Blocks are individual heap allocations */
            std::atomic<void*>      free_list_   = NULLPTR;
            std::atomic<UInt32>     free_count_  = 0;
            UInt32                  block_size_  = 0;
            UInt32                  block_count_ = 0;
            UInt32                  index_       = 0;   /**< Pool tier index */
            std::atomic<bool>       destroyed_   = false;  /**< Set by ShutdownPools: stop all Acquire/Release writes */
            mutable std::mutex      sync_;       /**< Serializes global list access */
            friend struct BufPoolLocal;  // per-thread cache access
        };

        /**
         * @brief Reference-counted packet buffer (zero-copy, movable).
         */
        class BufRef {
        public:
            BufRef() noexcept = default;
            // No virtual dtor: BufRef is never derived from (no polymorphic
            // use; BufPool is a separate class) - dropping the vtable saves a
            // vptr per object and an indirect call per destruction on the
            // per-packet hot path. Deliberately not 'final' - the absence of
            // virtuals makes the dtor non-polymorphic by construction.
            ~BufRef() noexcept;
            BufRef(const BufRef&) = delete;
            BufRef& operator=(const BufRef&) = delete;
            BufRef(BufRef&& other) noexcept;
            BufRef& operator=(BufRef&& other) noexcept;

            /**
             * @brief Acquires a buffer from the tiered pools.
             * @param min_size Minimum payload bytes required.
             * @return BufRef owning a buffer, or empty when pools exhausted.
             */
            static BufRef Acquire(UInt32 min_size) noexcept;
            /**
             * @brief Creates a shared handle (increments the refcount).
             * @note Payload bytes are shared, never copied.
             */
            BufRef Clone() noexcept {
                BufRef copy;
                copy.pool_ = pool_;
                copy.refs_ = refs_;
                copy.data_ = data_;
                copy.capacity_ = capacity_;
                copy.len_ = len_;
                copy.meta_ = meta_;
                if (NULLPTR != refs_) {
                    // relaxed: incrementing a refcount needs no release/acquire
                    // ordering — only the decrement that reaches zero (Unref's
                    // acq_rel fetch_sub) must synchronize with the pool return.
                    // Matches Ref()'s relaxed increment (bufref.cpp). Calling
                    // constraint: Clone()/Ref()/Unref() on a shared handle must
                    // never race with the last Unref(), or the block may already
                    // be back in the pool (use-after-free).
                    refs_->fetch_add(1, std::memory_order_relaxed);
                }
                return copy;
            }
            /**
             * @brief Increments the reference count.
             */
            void Ref() noexcept;
            /**
             * @brief Decrements; returns the block to its pool at zero.
             */
            void Unref() noexcept;
            /**
             * @brief Payload pointer.
             */
            Byte* Data() noexcept { return data_; }
            /**
             * @brief Payload pointer (const view).
             */
            const Byte* Data() const noexcept { return data_; }
            /**
             * @brief Payload capacity in bytes.
             */
            UInt32 Capacity() const noexcept { return capacity_; }
            /**
             * @brief Logical payload length.
             */
            UInt32 Len() const noexcept { return len_; }
            /**
             * @brief Sets the logical payload length.
             */
            void SetLen(UInt32 len) noexcept { len_ = (len <= capacity_) ? len : capacity_; }
            /**
             * @brief Current reference count.
             */
            UInt32 UseCount() const noexcept;
            /**
             * @brief GSO metadata (valid when segs > 0).
             */
            SegMeta& Meta() noexcept { return meta_; }
            /**
             * @brief GSO metadata (const view).
             */
            const SegMeta& Meta() const noexcept { return meta_; }
            /**
             * @brief True when this ref owns no buffer.
             */
            bool IsEmpty() const noexcept { return NULLPTR == data_; }

        private:
            static BufRef AcquireFrom(BufPool& pool, Byte* payload) noexcept;
            static Byte* AcquireArena(UInt32 min_size, bool tx_class, BufPool*& selected) noexcept;
            void Release() noexcept;

            BufPool*    pool_     = NULLPTR;
            std::atomic<UInt32>* refs_ = NULLPTR;
            Byte*       data_     = NULLPTR;
            UInt32      capacity_ = 0;
            UInt32      len_      = 0;
            SegMeta     meta_;
        };

        /**
         * @brief Default packet buffer tiers: 2KB / 4KB / 32KB.
         */
        void InitPools() noexcept;
        /**
         * @brief Marks all tiered pools destroyed and returns this thread's
         *        cached blocks. The arenas are NOT freed here (freeing them
         *        concurrently with a peer thread's Acquire/Release is a
         *        use-after-free window); the PoolRegistry's static destructor
         *        frees every pool at process exit. After this call Acquire
         *        returns empty and Release drops blocks.
         */
        void ShutdownPools() noexcept;

        // A bounded arena burst protects a persistently denied sender.
        // The connection serializes Acquire/Cancel. Queue/grant publication
        // uses the global mutex; a published grant belongs only to its owner.
        class TxWaiter {
        public:
            TxWaiter() noexcept = default;
            ~TxWaiter() noexcept;
            void Cancel() noexcept;
            void ReleaseUnused() noexcept;
            bool IsWaiting() const noexcept { return active_.load(std::memory_order_acquire); }
            TxWaiter(const TxWaiter&) = delete;
            TxWaiter& operator=(const TxWaiter&) = delete;
        private:
            friend class BufRef;
            void EnqueueNoLock(UInt32 size) noexcept;
            void UnlinkNoLock() noexcept;
            BufRef TakeGrant(UInt32 size) noexcept;
            std::atomic<bool> active_{false};
            std::atomic<bool> granted_{false};
            bool queued_ = false;
            UInt32 size_ = 0;
            UInt32 denials_ = 0;
            TxWaiter* prev_ = NULLPTR;
            TxWaiter* next_ = NULLPTR;
            BufRef ready_;
            std::unique_ptr<BufRef[]> extra_;
            UInt32 extra_count_ = 0;
        };

        /**
         * @brief Global packet-memory pressure gate for NEW transmit data
         *        (kernel tcp_memory_pressure / sk_wmem_schedule analogue).
         *
         * The tiered pools are shared by transmit retention (every unACKed
         * data segment holds its packet block until it is ACKed) and by
         * ingress (every received packet, including the pure ACKs that
         * release that retention). Without a split, enough concurrent
         * senders (flows x snd_buf > pool) consume every block, ingress
         * can no longer allocate, the ACKs that would free the blocks are
         * dropped, and the stack wedges permanently.
         *
         * Each tier keeps a headroom reserve (1/8 of its blocks) that new
         * transmit data may not consume. While a TxAcquireScope is alive on
         * the calling thread, BufRef::Acquire skips tiers at or below their
         * reserve and never uses the heap overflow; an empty result makes
         * the caller keep the data buffered (bounded by snd_buf) and retry
         * once ACKs free blocks. Ingress, ACKs, control segments and
         * retransmissions run outside the scope and keep using the full
         * pool plus the bounded heap overflow. When no tier is under
         * pressure the scope changes nothing. Keep the scope tight around
         * the packet build: a synchronous sink may process ingress
         * re-entrantly and that ingress must not be classed as transmit.
         */
        class TxAcquireScope {
        public:
            explicit TxAcquireScope(TxWaiter* waiter = NULLPTR) noexcept;
            ~TxAcquireScope() noexcept;
            TxAcquireScope(const TxAcquireScope&) = delete;
            TxAcquireScope& operator=(const TxAcquireScope&) = delete;
        private:
            bool prev_ = false;
            TxWaiter* prev_waiter_ = NULLPTR;
        };

        /**
         * @brief Pool-pressure telemetry (process-wide, monotonic counters
         *        except heap_overflow_bytes, which is the current level).
         */
        struct PoolPressureStats {
            UInt64 tx_deferrals = 0;           /**< TxAcquireScope acquisitions denied at the reserve */
            UInt64 heap_overflow_acquires = 0; /**< Blocks served from the bounded heap overflow */
            UInt64 heap_overflow_denials = 0;  /**< Overflow cap reached: Acquire returned empty */
            UInt64 heap_overflow_bytes = 0;    /**< Heap overflow bytes currently in use */
            UInt64 heap_overflow_peak = 0;     /**< High-water mark of heap_overflow_bytes */
        };
        PoolPressureStats GetPoolPressureStats() noexcept;

        /**
         * @brief Upper bound of the heap overflow used when every fitting
         *        tier is empty (last-resort backstop so ingress/ACK
         *        processing is never starved by a full arena).
         */
        constexpr UInt64 kHeapOverflowCapBytes = 8ull * 1024ull * 1024ull;
    }
}
