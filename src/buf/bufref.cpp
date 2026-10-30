/**
 * @file bufref.cpp
 * @brief Zero-copy buffer pool implementation.
 */

#include <xtcp/buf/bufref.h>

namespace xtcp {
    namespace buf {
        namespace {
            constexpr UInt32 kPoolCount = 3;
            BufPool* g_pools[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
            constexpr UInt32 kPoolSizes[kPoolCount] = { 2048, 4096, 32768 };
            // The small tiers carry ordinary TCP packets and their retransmit
            // references. A 4-flow, 1 MiB-per-flow test can retain >2,500 MSS
            // buffers at once, so the previous 1,536 small blocks exhausted
            // both tiers and converted ACK ingress into packet loss. Keep the
            // large-GRO tier bounded independently; the small tiers provide
            // enough packet capacity for the configured send-buffer envelope.
            constexpr UInt32 kPoolBlocks[kPoolCount] = { 8192, 4096, 128 };
            // Transmit headroom: new transmit data may not take a tier below
            // 1/8 of its blocks (see TxAdmit). The reserve keeps ingress -
            // above all the pure ACKs that release transmit retention -
            // allocatable when flows x snd_buf exceeds the arena.
            constexpr UInt32 kTxReserveShift = 3;
            constexpr UInt32 kTxFairBurstPackets = 32;
            // Age repeated allocation failures, not brief ACK-clock pressure.
            // Forcing every sender into FIFO fragments otherwise healthy GSO.
            constexpr UInt32 kTxFairWaitDenials = 256;

            // Heap overflow owners (one per tier) and the bounded overflow
            // accounting. Overflow blocks are plain heap allocations tagged
            // with the tier's overflow owner so BufRef/Release stay unchanged.
            BufPool* g_heap_pools[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
            std::atomic<UInt64> g_heap_bytes{ 0 };
            std::atomic<UInt64> g_heap_peak{ 0 };
            std::atomic<UInt64> g_heap_acquires{ 0 };
            std::atomic<UInt64> g_heap_denials{ 0 };
            std::atomic<UInt64> g_tx_deferrals{ 0 };
            // Set by TxAcquireScope: the current Acquire builds NEW data.
            thread_local bool t_tx_class = false;
            thread_local TxWaiter* t_tx_waiter = NULLPTR;
            std::mutex g_tx_wait_mutex;
            TxWaiter* g_tx_wait_head = NULLPTR;
            TxWaiter* g_tx_wait_tail = NULLPTR;
            std::atomic<UInt32> g_tx_wait_count{0};

            // Pool lifetime: pools are created by InitPools and are NEVER
            // freed by ShutdownPools. A concurrent Acquire/Release running on
            // another thread has no lock-free way to prove the pool is still
            // alive (the IsDestroyed check at Acquire entry is a TOCTOU vs
            // the shutdown delete), so freeing the arena at shutdown is a
            // use-after-free risk for exactly that window. Instead the
            // registry below owns every pool and frees them in its static
            // destructor (process exit) - LSan stays clean, and no thread can
            // ever touch a freed arena. ShutdownPools only marks the pools
            // destroyed (Acquire returns empty, Release drops blocks) and
            // resets the TLS caches; InitPools re-arms a destroyed pool on
            // re-init.
            struct PoolRegistry {
                BufPool* pools[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
                BufPool* heap_pools[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
                ~PoolRegistry() noexcept {
                    for (UInt32 i = 0; i < kPoolCount; ++i) {
                        delete pools[i];
                        delete heap_pools[i];
                    }
                }
            };
            PoolRegistry g_registry;

            // Per-thread cache cap per tier. BufPoolLocal::blocks is sized to
            // the largest cap (kLocalCapMax) so a single constant array works.
            // tier-2 (32KB) has only 128 blocks: a per-thread hoard of 16
            // lets >=8 threads starve the global free list, so its cap is
            // scaled down to 4 while tier-0 keeps 16.
            constexpr UInt32 kLocalCapMax = 16;
            // Per-thread cache cap per tier. tier-2 (32KB) hoarding is the
            // starvation root cause: only 128 blocks exist, and with any
            // nonzero cap >=32 threads can hoard the WHOLE pool in their
            // private caches while other threads see an empty global free
            // list (Acquire returns empty = silent packet loss). Cap 0
            // disables hoarding for tier-2 entirely: every release returns
            // the block to the global list immediately, so any thread can
            // reuse it. The cost is one extra atomic per large-buffer
            // release/acquire (rare - 32KB blocks) versus a structural
            // cross-thread starvation.
            constexpr UInt32 kLocalCaps[kPoolCount] = { 16, 8, 0 };

            /**
             * @brief Per-thread block cache: most Acquire/Release never touch
             *        the shared free list, eliminating cross-core contention.
             */
            struct BufPoolLocal {
                BufPool* pool[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
                Byte*    blocks[kPoolCount][kLocalCapMax];
                UInt32   count[kPoolCount] = { 0, 0, 0 };

                Byte* Take(UInt32 idx) noexcept {
                    if (0 < count[idx]) {
                        return blocks[idx][--count[idx]];
                    }
                    return NULLPTR;
                }
                void Put(BufPool* p, UInt32 idx, Byte* payload) noexcept {
                    // After ShutdownPools marks a pool destroyed, no thread
                    // may write blocks back into it (the arena may be freed).
                    // Drop the block instead; the leak is bounded by shutdown.
                    if (p->IsDestroyed()) {
                        return;
                    }
                    if (0 == kLocalCaps[idx]) {
                        // No-hoarding tier (tier-2): return straight to the
                        // global free list so released blocks are visible to
                        // every thread (starvation root fix).
                        p->FlushToGlobal(&payload, 1);
                        return;
                    }
                    if (kLocalCaps[idx] <= count[idx]) {
                        p->FlushToGlobal(blocks[idx], count[idx]);
                        count[idx] = 0;
                    }
                    blocks[idx][count[idx]++] = payload;
                }
                ~BufPoolLocal() noexcept {
                    for (UInt32 i = 0; i < kPoolCount; ++i) {
                        if (NULLPTR != pool[i] && 0 < count[i]) {
                            // Skip destroyed pools: their arena may already be
                            // freed, so flushing would be a use-after-free.
                            if (pool[i]->IsDestroyed()) {
                                count[i] = 0;
                                pool[i] = NULLPTR;
                                continue;
                            }
                            pool[i]->FlushToGlobal(blocks[i], count[i]);
                            count[i] = 0;
                        }
                    }
                }
            };
            thread_local BufPoolLocal t_local;
        }

        BufPool::BufPool(UInt32 block_size, UInt32 block_count) noexcept
            : block_size_(block_size), block_count_(block_count) {
            if (kHeaderBytes > block_size_) {
                block_size_ = kHeaderBytes;
            }
            // Assign the tier index by block size (matches kPoolSizes order).
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (block_size == kPoolSizes[i]) {
                    index_ = i;
                    break;
                }
            }
            if (0 == block_count_) {
                return;  // heap-overflow owner: no arena
            }
            arena_ = static_cast<Byte*>(xtcp::Malloc(static_cast<UInt64>(block_size_) * block_count_));
            if (NULLPTR == arena_) {
                block_count_ = 0;
                return;
            }
            void* head = NULLPTR;
            for (UInt32 i = 0; i < block_count_; ++i) {
                Byte* block = arena_ + static_cast<UInt64>(block_size_) * i;
                *reinterpret_cast<void**>(block) = head;
                head = block;
            }
            free_list_.store(head, std::memory_order_relaxed);
            free_count_.store(block_count_, std::memory_order_relaxed);
        }

        BufPool::~BufPool() noexcept {
            if (NULLPTR != arena_) {
                xtcp::Mfree(arena_);
            }
            arena_ = NULLPTR;
        }

        BufPool* BufPool::NewHeapOverflow(UInt32 block_size) noexcept {
            BufPool* p = new (std::nothrow) BufPool(block_size, 0);
            if (NULLPTR != p) {
                p->heap_overflow_ = true;
            }
            return p;
        }

        Byte* BufPool::Acquire() noexcept {
            // No acquisitions after ShutdownPools: the pool may be freed.
            if (IsDestroyed()) {
                return NULLPTR;
            }
            // Fast path: per-thread cache (lock-free). The slot is tier-
            // indexed, so only use it when THIS pool owns the cached blocks
            // - a second pool sharing the tier (user-created pools with a
            // matching block size) must never receive another pool's blocks.
            if (t_local.pool[index_] == this) {
                if (Byte* payload = t_local.Take(index_)) {
                    Byte* block = payload - kHeaderBytes;
                    *reinterpret_cast<BufPool**>(block) = this;
                    *reinterpret_cast<std::atomic<UInt32>*>(block + sizeof(void*)) = 1;
                    return payload;
                }
            }
            // Slow path: shared free list (mutex-serialized, ABA-safe).
            std::lock_guard<std::mutex> scope(sync_);
            void* block = free_list_.load(std::memory_order_relaxed);
            if (NULLPTR == block) {
                return NULLPTR;
            }
            free_list_.store(*reinterpret_cast<void**>(block), std::memory_order_relaxed);
            free_count_.fetch_sub(1, std::memory_order_relaxed);
            Byte* payload = static_cast<Byte*>(block) + kHeaderBytes;
            *reinterpret_cast<BufPool**>(block) = this;
            *reinterpret_cast<std::atomic<UInt32>*>(static_cast<Byte*>(block) + sizeof(void*)) = 1;
            return payload;
        }

        void BufPool::Release(Byte* payload) noexcept {
            if (heap_overflow_) {
                // Individually allocated overflow block: free it and return
                // its bytes to the overflow budget. Never cached per thread.
                xtcp::Mfree(payload - kHeaderBytes);
                g_heap_bytes.fetch_sub(block_size_, std::memory_order_relaxed);
                return;
            }
            // Fast path: cache locally (lock-free), flush in batches. Only
            // when THIS pool already owns the tier slot - a slot owned by a
            // different pool holds that pool's blocks, and caching ours
            // there would let a later flush push foreign blocks into our
            // global free list (cross-pool corruption).
            if (t_local.pool[index_] == this) {
                t_local.Put(this, index_, payload);
                return;
            }
            if (NULLPTR == t_local.pool[index_]) {
                t_local.pool[index_] = this;
                t_local.Put(this, index_, payload);
                return;
            }
            // Slot owned by another pool sharing this tier: bypass the
            // cache entirely and return straight to the global free list.
            FlushToGlobal(&payload, 1);
        }

        void BufPool::FlushToGlobal(Byte* const* payloads, UInt32 count) noexcept {
            std::lock_guard<std::mutex> scope(sync_);
            for (UInt32 i = 0; i < count; ++i) {
                Byte* block = payloads[i] - kHeaderBytes;
                *reinterpret_cast<void**>(block) = free_list_.load(std::memory_order_relaxed);
                free_list_.store(block, std::memory_order_relaxed);
            }
            free_count_.fetch_add(count, std::memory_order_relaxed);
        }

        BufRef::BufRef(BufRef&& other) noexcept {
            pool_ = other.pool_;
            refs_ = other.refs_;
            data_ = other.data_;
            capacity_ = other.capacity_;
            len_ = other.len_;
            meta_ = other.meta_;
            other.pool_ = NULLPTR;
            other.refs_ = NULLPTR;
            other.data_ = NULLPTR;
            other.capacity_ = 0;
            other.len_ = 0;
            other.meta_ = SegMeta();
        }

        BufRef& BufRef::operator=(BufRef&& other) noexcept {
            if (this != &other) {
                Unref();  // release this handle's reference first
                pool_ = other.pool_;
                refs_ = other.refs_;
                data_ = other.data_;
                capacity_ = other.capacity_;
                len_ = other.len_;
                meta_ = other.meta_;
                other.pool_ = NULLPTR;
                other.refs_ = NULLPTR;
                other.data_ = NULLPTR;
                other.capacity_ = 0;
                other.len_ = 0;
                other.meta_ = SegMeta();
            }
            return *this;
        }

        BufRef::~BufRef() noexcept {
            Unref();  // shared handles must not release the block until zero
        }

        Byte* BufRef::AcquireArena(UInt32 min_size, bool tx_class, BufPool*& selected) noexcept {
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                BufPool* pool = g_pools[i];
                if (NULLPTR == pool) {
                    continue;
                }
                if ((pool->BlockSize() - kHeaderBytes) >= min_size) {
                    // New transmit data may not dip into the tier's ingress
                    // headroom (TxAcquireScope). The global free count
                    // ignores per-thread caches, so this errs toward
                    // keeping more headroom, never less.
                    if (tx_class && pool->FreeCount() <= (pool->Capacity() >> kTxReserveShift)) {
                        continue;
                    }
                    Byte* payload = pool->Acquire();
                    if (NULLPTR != payload) {
                        selected = pool;
                        return payload;
                    }
                }
            }
            return NULLPTR;
        }

        BufRef BufRef::Acquire(UInt32 min_size) noexcept {
            const bool tx_class = t_tx_class;
            TxWaiter* waiter = tx_class ? t_tx_waiter : NULLPTR;
            if (NULLPTR != waiter && waiter->granted_.load(std::memory_order_acquire)) {
                BufRef ref = waiter->TakeGrant(min_size);
                if (!ref.IsEmpty()) return ref;
            }
            if (NULLPTR != waiter &&
                (waiter->active_.load(std::memory_order_acquire) ||
                 0 != g_tx_wait_count.load(std::memory_order_acquire))) {
                std::lock_guard<std::mutex> lock(g_tx_wait_mutex);
                if (waiter->granted_.load(std::memory_order_relaxed)) {
                    BufRef ref = waiter->TakeGrant(min_size);
                    if (!ref.IsEmpty()) return ref;
                }
                waiter->active_.store(waiter->queued_, std::memory_order_release);
                if (waiter->queued_) waiter->size_ = min_size;
                const auto available_payload = []() noexcept {
                    UInt32 largest = 0;
                    for (UInt32 i = 0; i < kPoolCount; ++i) {
                        const BufPool* pool = g_pools[i];
                        if (NULLPTR != pool && !pool->IsDestroyed() &&
                            pool->FreeCount() > (pool->Capacity() >> kTxReserveShift)) {
                            largest = pool->BlockSize() - kHeaderBytes;
                        }
                    }
                    return largest;
                };
                UInt32 available = available_payload();
                // Reserve a bounded burst for each older eligible waiter before
                // allowing an ACK-driven sender to refill. Skip size classes
                // that cannot allocate, so a 32K waiter cannot block MSS TX.
                for (TxWaiter* current = g_tx_wait_head; NULLPTR != current && available != 0;) {
                    TxWaiter* next = current->next_;
                    if (current->size_ <= available) {
                        BufPool* selected = NULLPTR;
                        Byte* payload = AcquireArena(current->size_, true, selected);
                        if (NULLPTR != payload) {
                            current->UnlinkNoLock();
                            current->ready_ = AcquireFrom(*selected, payload);
                            while (current->extra_ && current->extra_count_ < kTxFairBurstPackets - 1) {
                                payload = AcquireArena(current->size_, true, selected);
                                if (NULLPTR == payload) break;
                                current->extra_[current->extra_count_++] = AcquireFrom(*selected, payload);
                            }
                            // Unlinked entries now belong exclusively to their
                            // connection. Publish the complete burst once.
                            current->granted_.store(true, std::memory_order_release);
                        }
                        available = available_payload();
                    }
                    current = next;
                }
                if (waiter->granted_.load(std::memory_order_relaxed)) {
                    BufRef ref = waiter->TakeGrant(min_size);
                    if (!ref.IsEmpty()) return ref;
                }
                if (!waiter->queued_) {
                    BufPool* selected = NULLPTR;
                    Byte* payload = AcquireArena(min_size, true, selected);
                    if (NULLPTR != payload) {
                        waiter->denials_ = 0;
                        return AcquireFrom(*selected, payload);
                    }
                    if (waiter->denials_ < kTxFairWaitDenials) ++waiter->denials_;
                    if (waiter->denials_ == kTxFairWaitDenials) waiter->EnqueueNoLock(min_size);
                }
                g_tx_deferrals.fetch_add(1, std::memory_order_relaxed);
                return BufRef();
            }
            BufPool* selected = NULLPTR;
            Byte* payload = AcquireArena(min_size, tx_class, selected);
            if (NULLPTR != payload) {
                if (NULLPTR != waiter) waiter->denials_ = 0;
                return AcquireFrom(*selected, payload);
            }
            if (tx_class) {
                if (NULLPTR != waiter) {
                    if (waiter->denials_ < kTxFairWaitDenials) ++waiter->denials_;
                    if (waiter->denials_ == kTxFairWaitDenials) {
                        std::lock_guard<std::mutex> lock(g_tx_wait_mutex);
                        waiter->EnqueueNoLock(min_size);
                    }
                }
                // Transmit data never uses the heap overflow: it stays
                // buffered (bounded by snd_buf) until ACKs free blocks.
                g_tx_deferrals.fetch_add(1, std::memory_order_relaxed);
                return BufRef();
            }
            // Every fitting tier is empty: serve the smallest fitting size
            // class from the bounded heap overflow so ingress and control
            // traffic keep flowing under pool pressure. New transmit data
            // never gets here (see above), so the overflow is ingress,
            // ACK and retransmission headroom only.
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                BufPool* heap = g_heap_pools[i];
                BufPool* pool = g_pools[i];
                if (NULLPTR == heap || NULLPTR == pool || pool->IsDestroyed()) {
                    continue;
                }
                const UInt32 block = heap->BlockSize();
                if ((block - kHeaderBytes) < min_size) {
                    continue;
                }
                const UInt64 prev = g_heap_bytes.fetch_add(block, std::memory_order_relaxed);
                if (prev + block > kHeapOverflowCapBytes) {
                    g_heap_bytes.fetch_sub(block, std::memory_order_relaxed);
                    g_heap_denials.fetch_add(1, std::memory_order_relaxed);
                    return BufRef();
                }
                Byte* raw = static_cast<Byte*>(xtcp::Malloc(block));
                if (NULLPTR == raw) {
                    g_heap_bytes.fetch_sub(block, std::memory_order_relaxed);
                    g_heap_denials.fetch_add(1, std::memory_order_relaxed);
                    return BufRef();
                }
                UInt64 peak = g_heap_peak.load(std::memory_order_relaxed);
                while (prev + block > peak &&
                       !g_heap_peak.compare_exchange_weak(peak, prev + block, std::memory_order_relaxed)) {
                }
                g_heap_acquires.fetch_add(1, std::memory_order_relaxed);
                *reinterpret_cast<BufPool**>(raw) = heap;
                *reinterpret_cast<std::atomic<UInt32>*>(raw + sizeof(void*)) = 1;
                return AcquireFrom(*heap, raw + kHeaderBytes);
            }
            return BufRef();
        }

        BufRef TxWaiter::TakeGrant(UInt32 size) noexcept {
            // Called only after acquiring a published grant; Acquire/Cancel
            // on this connection are serialized by its owner, not this mutex.
            BufRef result;
            while (extra_count_ > 0) {
                BufRef& ref = extra_[--extra_count_];
                if (ref.Capacity() >= size) {
                    result = std::move(ref);
                    break;
                }
                ref = BufRef();
            }
            if (result.IsEmpty() && !ready_.IsEmpty()) {
                if (ready_.Capacity() >= size) result = std::move(ready_);
                else ready_ = BufRef();
            }
            const bool held = extra_count_ > 0 || !ready_.IsEmpty();
            granted_.store(held, std::memory_order_release);
            active_.store(held, std::memory_order_release);
            if (!result.IsEmpty()) denials_ = 0;
            return result;
        }

        void TxWaiter::EnqueueNoLock(UInt32 size) noexcept {
            size_ = size;
            if (queued_) return;
            if (!extra_) extra_.reset(new (std::nothrow) BufRef[kTxFairBurstPackets - 1]);
            prev_ = g_tx_wait_tail;
            if (NULLPTR != prev_) prev_->next_ = this;
            else g_tx_wait_head = this;
            g_tx_wait_tail = this;
            queued_ = true;
            active_.store(true, std::memory_order_release);
            g_tx_wait_count.fetch_add(1, std::memory_order_release);
        }

        void TxWaiter::UnlinkNoLock() noexcept {
            if (!queued_) return;
            if (NULLPTR != prev_) prev_->next_ = next_;
            else g_tx_wait_head = next_;
            if (NULLPTR != next_) next_->prev_ = prev_;
            else g_tx_wait_tail = prev_;
            prev_ = next_ = NULLPTR;
            queued_ = false;
            g_tx_wait_count.fetch_sub(1, std::memory_order_release);
        }

        void TxWaiter::Cancel() noexcept {
            denials_ = 0;
            if (!active_.load(std::memory_order_acquire)) return;
            std::lock_guard<std::mutex> lock(g_tx_wait_mutex);
            UnlinkNoLock();
            while (extra_count_ > 0) extra_[--extra_count_] = BufRef();
            ready_ = BufRef();
            granted_.store(false, std::memory_order_release);
            active_.store(false, std::memory_order_release);
        }

        void TxWaiter::ReleaseUnused() noexcept {
            if (!active_.load(std::memory_order_acquire)) return;
            std::lock_guard<std::mutex> lock(g_tx_wait_mutex);
            while (extra_count_ > 0) extra_[--extra_count_] = BufRef();
            // Keep one protected packet and the FIFO turn across pacing/window stops.
            granted_.store(!ready_.IsEmpty(), std::memory_order_release);
            active_.store(queued_ || !ready_.IsEmpty(), std::memory_order_release);
        }

        TxWaiter::~TxWaiter() noexcept { Cancel(); }

        TxAcquireScope::TxAcquireScope(TxWaiter* waiter) noexcept
            : prev_(t_tx_class), prev_waiter_(t_tx_waiter) {
            t_tx_class = true;
            t_tx_waiter = waiter;
        }

        TxAcquireScope::~TxAcquireScope() noexcept {
            t_tx_class = prev_;
            t_tx_waiter = prev_waiter_;
        }

        PoolPressureStats GetPoolPressureStats() noexcept {
            PoolPressureStats s;
            s.tx_deferrals = g_tx_deferrals.load(std::memory_order_relaxed);
            s.heap_overflow_acquires = g_heap_acquires.load(std::memory_order_relaxed);
            s.heap_overflow_denials = g_heap_denials.load(std::memory_order_relaxed);
            s.heap_overflow_bytes = g_heap_bytes.load(std::memory_order_relaxed);
            s.heap_overflow_peak = g_heap_peak.load(std::memory_order_relaxed);
            return s;
        }

        BufRef BufRef::AcquireFrom(BufPool& pool, Byte* payload) noexcept {
            BufRef ref;
            ref.pool_ = &pool;
            ref.data_ = payload;
            ref.capacity_ = pool.BlockSize() - kHeaderBytes;
            ref.len_ = 0;
            ref.refs_ = reinterpret_cast<std::atomic<UInt32>*>(payload - kHeaderBytes + sizeof(void*));
            return ref;
        }

        void BufRef::Ref() noexcept {
            if (NULLPTR != refs_) {
                refs_->fetch_add(1, std::memory_order_relaxed);
            }
        }

        void BufRef::Unref() noexcept {
            if (NULLPTR != refs_) {
                if (1 == refs_->fetch_sub(1, std::memory_order_acq_rel)) {
                    Release();
                }
            }
        }

        void BufRef::Release() noexcept {
            if (NULLPTR != data_) {
                pool_->Release(data_);
            }
            pool_ = NULLPTR;
            refs_ = NULLPTR;
            data_ = NULLPTR;
            capacity_ = 0;
            len_ = 0;
            meta_ = SegMeta();  // match the move semantics: no stale GSO metadata on an empty handle
        }

        UInt32 BufRef::UseCount() const noexcept {
            if (NULLPTR == refs_) {
                return 0;
            }
            return refs_->load(std::memory_order_relaxed);
        }

        void InitPools() noexcept {
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (NULLPTR == g_pools[i]) {
                    BufPool* p = new (std::nothrow) BufPool(kPoolSizes[i], kPoolBlocks[i]);
                    g_pools[i] = p;
                    g_registry.pools[i] = p;
                    if (NULLPTR == g_heap_pools[i]) {
                        BufPool* h = BufPool::NewHeapOverflow(kPoolSizes[i]);
                        g_heap_pools[i] = h;
                        g_registry.heap_pools[i] = h;
                    }
                } else if (g_pools[i]->IsDestroyed()) {
                    // Re-init after ShutdownPools: re-arm the same pool
                    // (its arena is still allocated - the registry frees it
                    // at process exit).
                    g_pools[i]->ResetDestroyed();
                }
            }
        }

        void ShutdownPools() noexcept {
            // Step 1: mark every pool destroyed BEFORE any frees. From this
            // point any Acquire returns empty and any Release/thread-cache
            // flush drops blocks instead of writing to a pool that may be
            // freed (Bug 2: other threads' caches and outstanding BufRefs
            // must never touch a freed arena).
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (NULLPTR != g_pools[i]) {
                    g_pools[i]->MarkDestroyed();
                }
            }
            // Step 2: return this thread's cached blocks to their pools'
            // global free lists (safe: the pools are still allocated here).
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (NULLPTR != t_local.pool[i] && 0 < t_local.count[i]) {
                    t_local.pool[i]->FlushToGlobal(t_local.blocks[i], t_local.count[i]);
                    t_local.count[i] = 0;
                    t_local.pool[i] = NULLPTR;
                }
            }
            // Step 3: the pools are NOT freed here (see the PoolRegistry
            // note above): freeing the arena while another thread may be
            // mid-Acquire/Release is a use-after-free (the IsDestroyed check
            // at Acquire entry is a TOCTOU vs this delete). The registry's
            // static destructor frees every pool at process exit, keeping
            // LSan clean without any concurrency window.
        }
    }
}
