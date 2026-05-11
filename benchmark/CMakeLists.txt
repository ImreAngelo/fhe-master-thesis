##
## Benchmark suite — Google Benchmark, one binary per source file.
## Mirrors test/CMakeLists.txt but links benchmark::benchmark instead of GTest.
##

include(FetchContent)
FetchContent_Declare(googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.9.1
)
set(BENCHMARK_ENABLE_TESTING       OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL       OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS   OFF CACHE BOOL "" FORCE)
set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

# ── register_benchmark(name [SOURCE stem]) ───────────────────────────────────
# name   - target name; must start with "bench-" (matches "make bench-<stem>")
# SOURCE - source file stem without .cpp (defaults to name if omitted)
function(register_benchmark name)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "" "SOURCE" "")
    if(ARG_SOURCE)
        set(_src ${ARG_SOURCE}.cpp)
    else()
        set(_src ${name}.cpp)
    endif()

    add_executable(${name} ${_src})
    target_link_libraries(${name} PRIVATE benchmark::benchmark server_lib)

    add_custom_target(run-${name}
        COMMAND $<TARGET_FILE:${name}> --benchmark_color=yes
        DEPENDS ${name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    set_property(GLOBAL APPEND PROPERTY ALL_BENCH_TARGETS ${name})
endfunction()

# ── Register benchmarks ──────────────────────────────────────────────────────
register_benchmark(bench-rgsw       SOURCE src/rgsw)
# register_benchmark(bench-write      SOURCE src/write)

# ── "make bench-all": build every benchmark binary ───────────────────────────
get_property(_all_benches GLOBAL PROPERTY ALL_BENCH_TARGETS)
add_custom_target(bench-all DEPENDS ${_all_benches})
