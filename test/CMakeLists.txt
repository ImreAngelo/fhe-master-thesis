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

# ── register_test(name [SOURCE stem] [CUSTOM_MAIN]) ──────────────────────────
# name        - CMake target name; must start with "test-" (matches "make test-<stem>")
# SOURCE      - source file stem without .cpp (defaults to name if omitted)
# CUSTOM_MAIN - the source file provides its own main(); link GTest::gtest
#               instead of GTest::gtest_main so the symbols don't collide.
#               Used by tests that parse extra CLI flags (see src/rgsw.cpp).
#
# Creates:
#   - executable target '<name>'         (excluded from bare "make")
#   - CTest entry for every TEST() case  (used by "make test" / ctest -R)
#   - custom target 'run-<name>'         (build + run just this binary)
function(register_test name)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "CUSTOM_MAIN" "SOURCE" "")
    if(ARG_SOURCE)
        set(_src ${ARG_SOURCE}.cpp)
    else()
        set(_src ${name}.cpp)
    endif()

    add_executable(${name} ${_src})

    # OpenFHE is already wired via link_libraries() in the root CMakeLists.
    # project_cxx20 bumps this target (only) to C++20; GTest stays at C++17.
    if(ARG_CUSTOM_MAIN)
        target_link_libraries(${name} PRIVATE GTest::gtest project_cxx20 server_lib)
    else()
        target_link_libraries(${name} PRIVATE GTest::gtest_main project_cxx20 server_lib)
    endif()

    # Force-include common.h before every translation unit in this target.
    # This makes gtest, openfhe, and shared helpers available without explicit includes.
    target_compile_options(${name} PRIVATE
        -include ${CMAKE_CURRENT_SOURCE_DIR}/common.h
    )

    # Register individual TEST() cases with CTest.
    gtest_discover_tests(${name})

    # "make run-<name>" rebuilds the binary if stale, then runs it directly.
    add_custom_target(run-${name}
        COMMAND $<TARGET_FILE:${name}> --gtest_color=yes
        DEPENDS ${name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    # Accumulate targets so the "check" target below can depend on all of them.
    set_property(GLOBAL APPEND PROPERTY ALL_TEST_TARGETS ${name})
endfunction()

# ── Register tests ───────────────────────────────────────────────────────────
# All targets are named "test-<stem>" so "make test-<stem>" works uniformly.
register_test(test-main             SOURCE src/main)
register_test(test-rgsw             SOURCE src/rgsw CUSTOM_MAIN)
register_test(test-homplacing       SOURCE src/homplacing)
register_test(test-homexpand        SOURCE src/homexpand)

# ── "make check" / "make test": rebuild all test binaries, run via CTest ─────
get_property(_all_tests GLOBAL PROPERTY ALL_TEST_TARGETS)
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${_all_tests}
)
