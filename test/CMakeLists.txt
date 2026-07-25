##
## This file sets up the unit tests located inside this directory 
## Pulls GoogleTest on the initial run
##

include(FetchContent)
FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE) # don't pollute the install prefix
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# ── register_test(name [SOURCE stem] [CUSTOM_MAIN] [LABELS ...]) ─────────────
# name        - CMake target name; must start with "test-" (matches "make test-<stem>")
# SOURCE      - source file stem without .cpp (defaults to name if omitted)
# CUSTOM_MAIN - the source file provides its own main(); link GTest::gtest
#               instead of GTest::gtest_main so the symbols don't collide.
# LABELS      - CTest labels applied to every discovered case. These drive test
#               subsetting ("ctest -L ci") and are orthogonal to crypto
#               parameters: every label runs the SAME params.toml set.
#
# Creates:
#   - executable target '<name>'         (excluded from bare "make")
#   - CTest entry for every TEST() case  (used by "make test" / ctest -R)
#   - custom target 'run-<name>'         (build + run just this binary)
function(register_test name)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "CUSTOM_MAIN" "SOURCE" "LABELS")
    if(ARG_SOURCE)
        set(_src ${ARG_SOURCE}.cpp)
    else()
        set(_src ${name}.cpp)
    endif()

    add_executable(${name} ${_src})

    # OpenFHE is already wired via link_libraries() in the root CMakeLists.
    # spar_utils brings core + spar/params.h; spar_client/spar_server are the protocol.
    if(ARG_CUSTOM_MAIN)
        target_link_libraries(${name} PRIVATE GTest::gtest spar_utils spar_client spar_server)
    else()
        target_link_libraries(${name} PRIVATE GTest::gtest_main spar_utils spar_client spar_server)
    endif()

    # Force-include common.h before every translation unit in this target.
    # This makes gtest, openfhe, and shared helpers available without explicit includes.
    target_compile_options(${name} PRIVATE
        -include ${CMAKE_CURRENT_SOURCE_DIR}/common.h
    )

    # Register individual TEST() cases with CTest.
    #
    # WORKING_DIRECTORY keeps RECORD_* CSV output in test/results/ whether the
    # binary is run via ctest or via "make run-test-<name>"; "make data" scans
    # test/results/.
    #
    # NO_PRETTY_VALUES strips the "# GetParam() = ..." comment that
    # --gtest_list_tests appends to every parameterized case. CMake's default
    # only rewrites that comment when the value suffix is a numeric index
    # (see the /[0-9]+ regex in GoogleTestAddTests.cmake); every suite here uses
    # a custom name generator, so the default leaves the comment verbatim — and
    # for a param type gtest cannot print, that comment is a raw byte dump.
    # Suppressing it keeps the generator's own name, e.g.
    #   BV/Products.External/standard   instead of
    #   BV/Products.External/standard  # GetParam() = 72-byte object <A0-CB ...>
    if(ARG_LABELS)
        gtest_discover_tests(${name}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            NO_PRETTY_VALUES
            PROPERTIES LABELS "${ARG_LABELS}"
        )
    else()
        gtest_discover_tests(${name}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            NO_PRETTY_VALUES
        )
    endif()

    # "make run-<name>" rebuilds the binary if stale, then runs it directly.
    add_custom_target(run-${name}
        COMMAND $<TARGET_FILE:${name}> --gtest_color=yes
        DEPENDS ${name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    # Accumulate targets so the "check" targets below can depend on them.
    set_property(GLOBAL APPEND PROPERTY ALL_TEST_TARGETS ${name})
    if("ci" IN_LIST ARG_LABELS)
        set_property(GLOBAL APPEND PROPERTY CI_TEST_TARGETS ${name})
    endif()
endfunction()

# ── Register tests ───────────────────────────────────────────────────────────
# All targets are named "test-<stem>" so "make test-<stem>" works uniformly.
# NOTE: src/rgsw.cpp is deliberately not registered — see the header comment in
# that file. It is kept for reference only.
register_test(test-products         SOURCE src/products     LABELS ci)
register_test(test-write            SOURCE src/write        LABELS ci)
register_test(test-multiparty       SOURCE src/multiparty   LABELS slow)

# ── "make check" / "make test": rebuild all test binaries, run via CTest ─────
get_property(_all_tests GLOBAL PROPERTY ALL_TEST_TARGETS)
get_property(_ci_tests  GLOBAL PROPERTY CI_TEST_TARGETS)
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${_all_tests}
)

# CI subset: builds and runs only the ci-labelled binaries. test-multiparty is
# excluded because it is minutes-long, NOT because it uses different parameters —
# every test runs the same params.toml set.
add_custom_target(check-ci
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L ci
    DEPENDS ${_ci_tests}
)
