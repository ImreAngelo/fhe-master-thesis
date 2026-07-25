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

include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)
### add directories for other OpenFHE modules as needed for your project

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

# Timing/logging macros in libs/core/include/core/utils/ are gated on DEBUG_TIMING
# / DEBUG_LOGGING. Off by default — opt in via `DEBUG=1 make test-<name>`,
# which passes -DENABLE_DEBUG_TIMING=ON / -DENABLE_DEBUG_LOGGING=ON.
option(ENABLE_DEBUG_TIMING  "Enable DEBUG_TIMER prints in core"  OFF)
option(ENABLE_DEBUG_LOGGING "Enable DEBUG_PRINT prints in core"  OFF)
if(ENABLE_DEBUG_TIMING)
    target_compile_definitions(core PUBLIC DEBUG_TIMING)
endif()
if(ENABLE_DEBUG_LOGGING)
    target_compile_definitions(core PUBLIC DEBUG_LOGGING)
endif()

# ── spar_client library: client-side protocol ────────────────────────────────
file(GLOB_RECURSE SPAR_CLIENT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/client/src/*.cpp"
)
add_library(spar_client STATIC ${SPAR_CLIENT_SOURCES})
target_include_directories(spar_client
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/libs/client/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/client/src
)
target_link_libraries(spar_client PUBLIC core)

# ── spar_server library: server-side protocol ────────────────────────────────
file(GLOB_RECURSE SPAR_SERVER_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/server/src/*.cpp"
)
add_library(spar_server STATIC ${SPAR_SERVER_SOURCES})
target_include_directories(spar_server
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/libs/server/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/server/src
)
target_link_libraries(spar_server PUBLIC core)

# ── Shared test/benchmark fixtures ───────────────────────────────────────────
# Header-only INTERFACE target. Parameter presets live in shared/params.h and
# are consumed by both test/ and benchmark/ — never by the libraries themselves.
add_library(spar_shared INTERFACE)
target_include_directories(spar_shared INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/shared)
target_link_libraries(spar_shared INTERFACE core spar_client spar_server)

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