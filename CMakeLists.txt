cmake_minimum_required(VERSION 3.16.3)

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac
###
### In order to create OpenFHE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: OPENFHEpke_static.a, OPENFHEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"

project(sPAR CXX)
set(CMAKE_CXX_STANDARD 17)
option(BUILD_STATIC "Set to ON to include static versions of the library" ON)

# Used here for toml++ (spar_utils) and again in test/ and benchmark/ for
# GoogleTest and Google Benchmark. All three land in ${BUILDDIR}/_deps.
include(FetchContent)

# Emit compile_commands.json so IDEs (VSCode, clangd, etc.) resolve all includes
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Static files are built into this directory (via -DCMAKE_INSTALL_PREFIX)
set(OpenFHE_DIR vendors/install/lib/OpenFHE)

find_package(OpenFHE CONFIG REQUIRED)
if(OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

# OpenFHE only defines PARALLEL inside its own build tree and does not export it
# in OpenFHE_CXX_FLAGS. Without it, OpenFHEParallelControls.GetThreadLimit() is
# compiled to return 1 in our translation units, silently disabling every
# num_threads(GetThreadLimit(...)) OpenMP loop in libs/.
add_compile_definitions(PARALLEL)

# SYSTEM (-isystem, not -I): OpenFHE_CXX_FLAGS above carries -Wall -Werror, and the
# first-party targets add -Wextra on top (see spar_warnings below). OpenFHE's headers
# do not build clean under -Wextra — the abstract bases in pke/schemebase/ alone raise
# dozens of -Wunused-parameter, which -Werror turns into build failures in whichever of
# OUR translation units happens to include them. SYSTEM silences diagnostics originating
# inside these headers while leaving our own code fully checked.
#
# Ordering note: -isystem paths are searched after every -I path, so the libs/*/include
# dirs now win a name clash instead of OpenFHE. That is the order the "spar/" include
# prefix was chosen for anyway (see the spar_utils comment below); OpenFHE-internal
# includes such as utils/exception.h still resolve, as nothing under libs/ shadows them.
include_directories(SYSTEM ${OPENMP_INCLUDES})
include_directories(SYSTEM ${OpenFHE_INCLUDE})
include_directories(SYSTEM ${OpenFHE_INCLUDE}/third-party/include)
include_directories(SYSTEM ${OpenFHE_INCLUDE}/core)
include_directories(SYSTEM ${OpenFHE_INCLUDE}/pke)
include_directories(SYSTEM ${OpenFHE_INCLUDE}/binfhe)
### add directories for other OpenFHE modules as needed for your project

# ── Sanitizers (-DENABLE_SANITIZERS=ON) ──────────────────────────────────────
# Off by default; `make sanitize` configures a separate build tree with it on.
# Must sit above the link_libraries() call below, which is where tcmalloc would
# otherwise enter the link line.
option(ENABLE_SANITIZERS "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

# Carrier for the instrumentation, linked PRIVATE into core, spar_client and
# spar_server below and nowhere else. The scheme and the protocol are what is
# under test; the test and benchmark binaries, spar_utils and the _deps
# dependencies are the harness around them, and instrumenting those only buys
# compile time and slower runs. Declared unconditionally and left empty when the
# option is off, so the target_link_libraries() lines below need no condition.
add_library(spar_sanitizers INTERFACE)

if(ENABLE_SANITIZERS)
    # -fno-sanitize=vptr: the check needs the whole class hierarchy instrumented,
    # and OpenFHE in vendors/install is not. Every OpenFHE-derived object we
    # touch would be reported as having a bad vptr.
    # -fno-sanitize-recover=all: UBSan defaults to printing and continuing, which
    # a green CI run would swallow. This turns the first finding into exit != 0.
    set(SPAR_SANITIZER_FLAGS
        -fsanitize=address,undefined
        -fno-sanitize=vptr
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g
    )
    target_compile_options(spar_sanitizers INTERFACE ${SPAR_SANITIZER_FLAGS})

    # Linking is the one part that cannot be narrowed: every executable that pulls
    # in an instrumented library needs the ASan/UBSan runtime, so this stays at
    # directory scope and covers the test and benchmark subdirectories too.
    #
    # Note what this still catches in the uninstrumented harness: ASan replaces the
    # allocator process-wide, so heap-buffer-overflow, use-after-free, double-free
    # and leaks are reported wherever they happen. Narrowing to libs/ gives up the
    # compile-time checks only — stack and global redzones, poisoned load/store,
    # and every UBSan check.
    add_link_options(${SPAR_SANITIZER_FLAGS})

    # tcmalloc replaces malloc/free wholesale, which collides head-on with ASan's
    # own allocator interception — the optimized install from `make openfhe` is
    # built WITH_TCM=ON and exports tcmalloc in the lists below. Dropping it hands
    # allocation back to glibc, i.e. to ASan. OpenFHE calls no tcmalloc-specific
    # symbol, so nothing else changes. (`make ci` builds WITH_TCM=OFF, where these
    # are no-ops.)
    list(REMOVE_ITEM OpenFHE_STATIC_LIBRARIES tcmalloc)
    list(REMOVE_ITEM OpenFHE_SHARED_LIBRARIES tcmalloc)
endif()

if(UNIX AND NOT APPLE)
    add_link_options(-Wl,--no-as-needed)
endif()

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
    link_libraries(${OpenFHE_STATIC_LIBRARIES})
else()
    set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
    link_libraries(${OpenFHE_SHARED_LIBRARIES})
endif()

# ── Warnings for first-party code ────────────────────────────────────────────
# Carried by an INTERFACE target rather than CMAKE_CXX_FLAGS: the latter is
# global and would also hit the FetchContent dependencies (toml++, GoogleTest,
# Google Benchmark) that configure under ${BUILDDIR}/_deps, plus anything else
# added to this tree. Link it PRIVATE into every target built from our own
# sources — the libraries below, and the test/benchmark binaries via
# register_test() / register_benchmark().
add_library(spar_warnings INTERFACE)
target_compile_options(spar_warnings INTERFACE -Wall -Wextra -Wshadow)

# ── Production binaries ──────────────────────────────────────────────────────
# Uncomment each line when the corresponding source exists.
# "make" / "make all" builds only what is listed here — tests are excluded.
#
# add_executable(simulate apps/simulate.cpp)
# add_executable(server   apps/server.cpp)

# ── core library: RGSW extension to OpenFHE (the scheme) ─────────────────────
# Reusable building block; not tied to the sPAR protocol. Public headers under
# libs/core/include/core/, private impl under libs/core/src/.
# CONFIGURE_DEPENDS re-globs on rebuild when files are added/removed.
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/core/src/*.cpp"
)
add_library(core STATIC ${CORE_SOURCES})
target_include_directories(core
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/libs/core/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/core/src
)
target_link_libraries(core PRIVATE spar_warnings spar_sanitizers)

# Timing/logging macros in libs/utils/include/spar/ are gated on DEBUG_TIMING /
# DEBUG_LOGGING. Off by default — opt in via `DEBUG=1 make test-<name>`, which
# passes -DENABLE_DEBUG_TIMING=ON / -DENABLE_DEBUG_LOGGING=ON. The definitions are
# attached to spar_utils below, which owns those headers; core no longer uses them.
option(ENABLE_DEBUG_TIMING  "Enable DEBUG_TIMER prints"  OFF)
option(ENABLE_DEBUG_LOGGING "Enable DEBUG_PRINT prints"  OFF)

# ── spar_client library: client-side protocol ────────────────────────────────
file(GLOB_RECURSE SPAR_CLIENT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/client/src/*.cpp"
)
add_library(spar_client STATIC ${SPAR_CLIENT_SOURCES})
target_include_directories(spar_client
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/libs/client/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/client/src
)
target_link_libraries(spar_client PUBLIC core PRIVATE spar_warnings spar_sanitizers)

# ── spar_server library: server-side protocol ────────────────────────────────
file(GLOB_RECURSE SPAR_SERVER_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/server/src/*.cpp"
)
add_library(spar_server STATIC ${SPAR_SERVER_SOURCES})
target_include_directories(spar_server
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/libs/server/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/server/src
)
target_link_libraries(spar_server PUBLIC core PRIVATE spar_warnings spar_sanitizers)

# ── spar_utils library: measurement helpers + runtime parameter loading ──────
# Sits ABOVE core in the dependency graph: params.cpp returns core::ExtendedContext
# via core::GenContextBV / core::GenContextHybrid. Nothing under libs/{core,client,
# server} may include spar/* — that would be a dependency cycle. If instrumentation
# is ever needed inside core, split the macro-only headers back down instead.
#
# The include prefix is "spar/", NOT "utils/": the root puts ${OpenFHE_INCLUDE}/core
# on the include path, so "utils/..." resolves to OpenFHE's own utils/ (see
# libs/core/src/context-bv.cpp, which includes utils/exception.h and utils/parallel.h).
FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

file(GLOB_RECURSE SPAR_UTILS_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/utils/src/*.cpp"
)
add_library(spar_utils STATIC ${SPAR_UTILS_SOURCES})
target_include_directories(spar_utils
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libs/utils/include
)
target_link_libraries(spar_utils PUBLIC core PRIVATE tomlplusplus::tomlplusplus spar_warnings)

# Absolute path so params.toml resolves identically from ctest's cwd (build/test/)
# and from the benchmark targets' cwd (benchmark/). $SPAR_PARAMS_FILE overrides it.
# PRIVATE: only params.cpp reads it, so it does not leak into every consumer TU.
target_compile_definitions(spar_utils PRIVATE
    SPAR_PARAMS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/params.toml"
)

if(ENABLE_DEBUG_TIMING)
    target_compile_definitions(spar_utils PUBLIC DEBUG_TIMING)
endif()
if(ENABLE_DEBUG_LOGGING)
    target_compile_definitions(spar_utils PUBLIC DEBUG_LOGGING)
endif()

# ── Test suite ───────────────────────────────────────────────────────────────
# enable_testing() must be called in the root so CMake generates CTestTestfile.cmake.
# Without it gtest_discover_tests() has nowhere to register tests and CTest reports
# "No tests were found".  EXCLUDE_FROM_ALL on the subdirectory still keeps every test
# binary out of the default "make" target.
enable_testing()
add_subdirectory(test EXCLUDE_FROM_ALL)

# ── Benchmark suite ──────────────────────────────────────────────────────────
# Same pattern as the test suite: kept out of the default "make" target.
add_subdirectory(benchmark EXCLUDE_FROM_ALL)