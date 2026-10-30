cmake_minimum_required(VERSION 3.16)

project(xtcp VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    # Keep PDBs in every configuration so crash dumps map to source lines.
    add_compile_options(/Zi)
    add_compile_options(/W4 /wd4819)
    add_link_options(/DEBUG)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Surface warnings on GCC/Clang; no MSVC 4819-equivalent encoding noise.
    add_compile_options(-Wall -Wextra)
endif()

option(XTCP_BUILD_TESTS "Build xtcp test suite" ON)
option(XTCP_BUILD_BENCH "Build xtcp benchmarks" OFF)
option(XTCP_BUILD_PLUGINS "Build xtcp example plugins" OFF)
option(XTCP_BUILD_CC_PLUGINS "Link built-in CC plugins (KCC/BBRv1/CUBIC) into xtcp_static" ON)
option(XTCP_SANITIZE "Build with ASan/UBSan (Linux) / CRT leak detection (MSVC)" OFF)
option(XTCP_CHECKSUM_VALIDATE
    "Validate received IPv4 header and TCP checksums (drops invalid packets; OFF keeps the
    hand-built-injection test suite working, ON is the production-recommended setting)" OFF)

add_library(xtcp_static STATIC
    src/xtcp.cpp
    src/ndi/manual.cpp
    src/zc/zc_probe.cpp
    src/core/mempool.cpp
    src/core/timer.cpp
    src/core/ip.cpp
    src/core/md5.cpp
    src/core/shard.cpp
    src/core/tcp_fsm.cpp
    src/qdisc/qdisc.cpp
    src/qdisc/fq.cpp
    src/qdisc/fq_codel.cpp
    src/qdisc/cake.cpp
    src/qdisc/fifo.cpp
    src/core/gso.cpp
    src/core/scheduler.cpp
    src/core/syncookies.cpp
    src/core/tfo.cpp
    src/plugin/plugin.cpp
    src/cc/cc.cpp
    src/core/stack.cpp
    src/options/options.cpp
    src/mimt/mimt.cpp
    src/async/async.cpp
    src/pcap/pcap_reader.cpp
    src/buf/bufref.cpp
)
if(XTCP_BUILD_CC_PLUGINS)
    target_sources(xtcp_static PRIVATE
        plugins/cc_kcc.cpp
        plugins/cc_bbrv1.cpp
        plugins/cc_cubic.cpp)
    target_include_directories(xtcp_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/plugins)
endif()
target_include_directories(xtcp_static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(xtcp_static PRIVATE XTCP_STATIC_BUILD)
if(NOT WIN32 AND CMAKE_DL_LIBS)
    # Linux: plugin.cpp's dlopen/dlclose live in libdl on pre-2.34 glibc
    # (MSVC needs nothing: LoadLibrary is in kernel32). Linking on the lib
    # keeps -ldl AFTER xtcp_static in every consumer's link line (a
    # target_link_libraries on the test puts it before the .a and the
    # linker reports "DSO missing from command line").
    target_link_libraries(xtcp_static PRIVATE ${CMAKE_DL_LIBS})
endif()
if(XTCP_CHECKSUM_VALIDATE)
    target_compile_definitions(xtcp_static PRIVATE XTCP_CHECKSUM_VALIDATE)
endif()
set_target_properties(xtcp_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(UNIX AND NOT APPLE)
    # The stack uses std::thread (manual backend threads, samples); link the
    # pthread library explicitly on Linux (Windows/APPLE provide it via the CRT).
    find_package(Threads REQUIRED)
    target_link_libraries(xtcp_static PUBLIC Threads::Threads)
endif()
if(WIN32 AND NOT MSVC)
    # MinGW: BCryptGenRandom (syncookies.cpp, tfo.cpp) and timeBeginPeriod
    # (high-resolution pacing timers) need explicit bcrypt/winmm links;
    # MSVC gets them via the vcpkg *.LIB wildcard.
    target_link_libraries(xtcp_static PUBLIC bcrypt winmm)
endif()

if(XTCP_SANITIZE)
    if(MSVC)
        target_compile_options(xtcp_static PRIVATE /fsanitize=address)
        target_link_options(xtcp_static PRIVATE /fsanitize=address)
    else()
        target_compile_options(xtcp_static PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(xtcp_static PRIVATE -fsanitize=address,undefined)
    endif()
endif()

if(XTCP_BUILD_TESTS)
    enable_testing()

    set(XTCP_TESTS
        test_smoke
        test_ndi
        test_ndi_tx_concurrency
        test_mempool
        test_bufref
        test_bufref_starvation
        test_timer
        test_zc_probe
        test_zc_rxpath
        test_gro_rx
        test_tso_tx
        test_tso_rto
        test_ts_paws
        test_ts_wrap
        test_ts_both_sides
        test_ts_ooo_drain
        test_urgent
        test_conn_info
        test_user_timeout
        test_eifel
        test_tlp
        test_rack
        test_dsack
        test_sack_option_budget
        test_ip
        test_pmtud
        test_mtu_probe
        test_shard
        test_tcp_fsm
        test_tcp_retransmit
        test_fq
        test_gso
        test_gso_stack
        test_gso_ipv6
        test_qdisc_fq_codel
        test_qdisc_cake
        test_qdisc_stack
        test_qdisc_threads
        test_keepalive
        test_keepalive_stack
        test_keepalive_dead
        test_nagle
        test_fin_retransmit
        test_finwait2_timeout
        test_close_pending
        test_simultaneous_close
        test_multi_drop
        test_scheduler
        test_plugin
        test_cc_bbr
        test_cc_kcc
        test_cc_selection
        test_md5
        test_md5_gso
        test_md5_loss
        test_md5_required
        test_md5_wildcard
        test_seq_wrap
        test_window_bound
        test_window_shrink
        test_ephemeral
        test_ipv6_stack
        test_sack_recovery
        test_conn_churn_threads
        test_conn_stress
        test_short_conn
        test_sndbuf_config
        test_lock_stress
        test_scale
        test_thread_data
        test_thread_send_abort
        test_tcp_opts
        test_wscale_stack
        test_wscale_transfer
        test_ecn
        test_ecn_offer
        test_tcp_handshake_api
        test_mss_negotiation
        test_stack
        test_ooo_capacity
        test_ooo_frontier
        test_options
        test_options_stack
        test_syncookies
        test_syncookie_flood
        test_syn_retries
        test_syn_cookie
        test_accept_reject
        test_rst_challenge
        test_rst_peer
        test_rst_closing
        test_fin_data
        test_close_recv
        test_closewait_fin
        test_timewait
        test_timewait_rst
        test_persist_handshake
        test_rcvbuf_config
        test_persist
        test_persist_stack
        test_ooo_flood
        test_fuzz
        test_mimt
        test_mimt_stack
        test_async
        test_tfo
        test_tfo_stack
        test_tfo_full
        test_tfo_first_data
        test_tfo_retransmit
        test_full_stack
        test_preconnect_send
        test_conn_churn
        test_mixed_load
        test_tfo_timewait
        test_quick_reconnect
        test_simultaneous_open
        test_pmtu
        test_pmtu_reprobe
        test_finwait2
        test_bench
        test_e2e
        test_diff_harness
        test_pcap
        test_finwait_data
        test_ooo_fin
        test_fin_ooo_closing
        test_mss_malformed
        test_cookie_mss_zero
        test_zero_window_backpressure
        test_mss_zero
        test_ecn_bidi
        test_ecn_cc
        test_rcv_mss_ack
        test_ecn_cwr
        test_retries_cap
        test_window_sndwl
        test_md5_rst
        test_tfo_md5_mutex
        test_tfo_cookie16
        test_syncookie_md5
        test_icmp_spoof
        test_flowmap_reuse
        test_challenge_limit
        test_synrst_closedport
        test_seqwrap_rst
        test_mimt_close_cb
        test_async_fail
        test_scheduler_cap
        test_ack_carry
        test_async_qdisc
        test_async_qdisc_multi
        test_async_qdisc_threads
        test_frag_align
        test_frag6
        test_bufpool_identity
        test_scale_shard_balance
        test_wscale_half
        test_sack_gap_edge
        test_pacing_flush
        test_karn_rtt
        test_half_ooo_window
        test_fastrec_reno
        test_fastrec_undo
        test_reorder_gate
        test_early_retx
        test_pmtu_md5
        test_ecn_loss
        test_keepalive_data
        test_tfo_synloss
        test_ooo_overlap
        test_async_listen_dup
        test_async_stop_listen
        test_md5_key_change
        test_wscale_zerowin
        test_checksum_simd
        test_close_synrcvd
        test_close_rst_comb
        test_pacing_update
        test_synretx_nonce
        test_ooo_partial
        test_halfclose_rto
        test_retx_windowshrink
        test_cookie_replay
        test_cookie_expiry
        test_closewait_data
        test_mtu_floor_md5
        test_mimt_write_block
        test_mimt_threads
        test_mimt_stack_lifetime
        test_mimt_connect_flow
        test_cc_unregister
        test_sndwl_multi
        test_conn_toctou
        test_challenge_interleave
        test_challenge_rate
        test_rst_keepalive
        test_tfo_early_ack
        test_mimt_close_prop
        test_state_change_cb
        test_ipv6_cookie_hash
        test_mtu_reprobe_pmtu
        test_synretx_md5
        test_rst_established_valid
        test_rst_storm
        test_wscale_bigbuf
        test_md5_mtu_dyn
        test_tfo_ecn
        test_halfclose_echo
        test_ack_storm
        test_multi_close_churn
        test_keepalive_rearm
        test_keepalive_states
        test_loss_recovery
        test_keepalive_zero
        test_window_edge_rst
        test_syn_cookie_data
        test_rto_recovery
        test_md5_large
        test_pmtu_reprobe_md5
        test_mimt_multi_flow
        test_async_concurrent
        test_qdisc_pacing
        test_ooo_mixed
        test_close_recv_md5
        test_combo_stress
        test_cc_default
        test_frag_timeout
        test_fifo
        test_1mb_stream
        test_bidi_1mb
        test_api_semantics
        test_endpoint_getter
        test_stop_listen
        test_txqueue_overflow
        test_tx_backpressure
        test_tx_retry_mpsc
        test_qdisc_rate_bridge
        test_qdisc_remove_flow
        test_qdisc_batch
    )
    if(UNIX AND NOT APPLE)
        list(APPEND XTCP_TESTS test_interop_linux)
    endif()
    if(XTCP_BUILD_LWIP)
        list(APPEND XTCP_TESTS test_lwip_interop)
    endif()

    foreach(XTCP_TEST IN LISTS XTCP_TESTS)
        add_executable(${XTCP_TEST}
            tests/${XTCP_TEST}.cpp
        )
        if(${XTCP_TEST} STREQUAL "test_plugin")
            target_sources(${XTCP_TEST} PRIVATE plugins/plugin_sample.cpp)
        endif()
        if(NOT XTCP_BUILD_CC_PLUGINS)
        if(${XTCP_TEST} STREQUAL "test_cc_bbr")
            target_sources(${XTCP_TEST} PRIVATE
                plugins/cc_bbrv1.cpp
                plugins/cc_cubic.cpp)
        endif()
        if(${XTCP_TEST} STREQUAL "test_cc_kcc")
            target_sources(${XTCP_TEST} PRIVATE
                plugins/cc_kcc.cpp)
        endif()
        if(${XTCP_TEST} STREQUAL "test_e2e")
            target_sources(${XTCP_TEST} PRIVATE
                plugins/cc_kcc.cpp
                plugins/cc_bbrv1.cpp
                plugins/cc_cubic.cpp)
        endif()
        endif()
        if(${XTCP_TEST} STREQUAL "test_cc_bbr" OR ${XTCP_TEST} STREQUAL "test_cc_kcc" OR ${XTCP_TEST} STREQUAL "test_e2e")
            target_include_directories(${XTCP_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/plugins)
        endif()
        if(${XTCP_TEST} STREQUAL "test_diff_harness")
            target_include_directories(${XTCP_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        endif()
        target_link_libraries(${XTCP_TEST} PRIVATE xtcp_static)
        if(${XTCP_TEST} STREQUAL "test_lwip_interop")
            target_link_libraries(${XTCP_TEST} PRIVATE lwip_static)
            target_include_directories(${XTCP_TEST} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/my
                ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/include
                ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/include/ipv4)
        endif()
        if(XTCP_SANITIZE)
            if(MSVC)
                target_compile_options(${XTCP_TEST} PRIVATE /fsanitize=address)
                target_link_options(${XTCP_TEST} PRIVATE /fsanitize=address)
            else()
                target_compile_options(${XTCP_TEST} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
                target_link_options(${XTCP_TEST} PRIVATE -fsanitize=address,undefined)
            endif()
        endif()
        add_test(NAME ${XTCP_TEST} COMMAND ${XTCP_TEST})
    endforeach()
endif()

if(XTCP_BUILD_BENCH)
add_executable(bench_throughput
    bench/bench_throughput.cpp
)
target_link_libraries(bench_throughput PRIVATE xtcp_static)

add_executable(bench_conns
    bench/bench_conns.cpp
)
target_link_libraries(bench_conns PRIVATE xtcp_static)

add_executable(bench_syn_rate
    bench/bench_syn_rate.cpp
)
target_link_libraries(bench_syn_rate PRIVATE xtcp_static)

add_executable(bench_multi_data
    bench/bench_multi_data.cpp
)
target_link_libraries(bench_multi_data PRIVATE xtcp_static)

add_executable(bench_multi_thread
    bench/multi_thread.cpp
)
target_link_libraries(bench_multi_thread PRIVATE xtcp_static)
if(MSVC)
    target_compile_options(bench_multi_thread PRIVATE /EHa)
endif()

add_executable(bench_thread_e2e
    bench/bench_thread_e2e.cpp
)
target_link_libraries(bench_thread_e2e PRIVATE xtcp_static)
if(MSVC)
    target_compile_options(bench_thread_e2e PRIVATE /EHa)
endif()
if(XTCP_SANITIZE)
    if(MSVC)
        target_compile_options(bench_multi_thread PRIVATE /fsanitize=address)
        target_link_options(bench_multi_thread PRIVATE /fsanitize=address)
    else()
        target_compile_options(bench_multi_thread PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(bench_multi_thread PRIVATE -fsanitize=address,undefined)
    endif()
endif()
endif()

option(XTCP_BUILD_SAMPLES "Build xtcp sample programs" OFF)
option(XTCP_BUILD_LWIP "Build lwIP for symmetric cross-validation" OFF)
if(XTCP_BUILD_SAMPLES)
    # Dual-mode echo (server/client): cross-platform, in-memory backends.
    add_executable(echo
        samples/echo.cpp
    )
    target_include_directories(echo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(echo PRIVATE xtcp_static)
    if(XTCP_SANITIZE)
        target_compile_options(echo PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(echo PRIVATE -fsanitize=address,undefined)
    endif()
endif()
if(XTCP_BUILD_SAMPLES AND UNIX AND NOT APPLE)
    set(XTCP_SAMPLE_TARGETS tun2socks interop_tun interop_tun6 interop_tun2 interop_tun2_6 interop_perf interop_perf6 interop_latency interop_latency6 interop_fair interop_fair6 interop_frag6 interop_md5 interop_md5_6 interop_tfo interop_tfo6 interop_ecn interop_ecn6 interop_loss interop_loss6 interop_zwin interop_zwin6 interop_keepalive interop_keepalive6 interop_mimt interop_mimt6 interop_churn interop_churn6 interop_threads interop_threads6 interop_qdisc interop_qdisc6 interop_cookie interop_tso interop_gro interop_urgent)
    foreach(XTCP_SAMPLE IN LISTS XTCP_SAMPLE_TARGETS)
        add_executable(${XTCP_SAMPLE}
            samples/${XTCP_SAMPLE}/main.cpp
            samples/tun2socks/tun_ndi.cpp
        )
        target_include_directories(${XTCP_SAMPLE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(${XTCP_SAMPLE} PRIVATE xtcp_static)
        if(XTCP_SANITIZE)
            target_compile_options(${XTCP_SAMPLE} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${XTCP_SAMPLE} PRIVATE -fsanitize=address,undefined)
        endif()
    endforeach()
endif()

if(XTCP_BUILD_LWIP)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/lwip_sources.cmake)
    list(LENGTH LWIP_SOURCES LWIP_N)
    message(STATUS "lwip files: ${LWIP_N}")
    if(NOT LWIP_SOURCES)
        message(FATAL_ERROR "lwip source list is empty")
    endif()
    add_library(lwip_static STATIC ${LWIP_SOURCES})
    target_include_directories(lwip_static PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/my
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/include/ipv4
    )
    if(MSVC)
        target_compile_options(lwip_static PRIVATE /W3)
    else()
        target_compile_options(lwip_static PRIVATE -w)
    endif()
endif()

if(XTCP_BUILD_PLUGINS)
    add_library(test_plugin_dll MODULE tests/test_plugin_dll.cpp)
    target_include_directories(test_plugin_dll PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(WIN32)
        set_target_properties(test_plugin_dll PROPERTIES PREFIX "" OUTPUT_NAME test_plugin_dll)
    endif()
    add_dependencies(test_plugin test_plugin_dll)
    # Only when the DLL target exists: test_plugin's dynamic-load test must
    # not fail on a default (XTCP_BUILD_PLUGINS=OFF) build, where no DLL is
    # produced (previously the Windows-only TestDynamicModule ran
    # unconditionally and Load() returned 0 -> CHECK failed).
    target_compile_definitions(test_plugin PRIVATE XTCP_HAVE_TEST_DLL)
    set_target_properties(test_plugin_dll PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:test_plugin>
        RUNTIME_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:test_plugin>)
endif()






