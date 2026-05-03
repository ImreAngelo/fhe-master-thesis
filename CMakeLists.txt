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

###
### Include source files
include_directories(src)

# ── Production binaries ──────────────────────────────────────────────────────
# Uncomment each line when the corresponding source exists.
# "make" / "make all" builds only what is listed here — tests are excluded.
#
# add_executable(app    src/main.cpp)
# add_executable(client src/client/main.cpp)
# add_executable(server src/server/main.cpp)

# ── Core library ─────────────────────────────────────────────────────────────
add_library(core_lib STATIC src/core/context.cpp)

# Timing/logging macros in src/utils/timer.h are gated on DEBUG_TIMING /
# DEBUG_LOGGING. Tests force-include common.h which sets these for test TUs,
# but core_lib compiles separately, so we propagate them here as well.
option(ENABLE_DEBUG_TIMING  "Enable DEBUG_TIMER prints in core_lib"  ON)
option(ENABLE_DEBUG_LOGGING "Enable DEBUG_PRINT prints in core_lib" ON)
if(ENABLE_DEBUG_TIMING)
    target_compile_definitions(core_lib PUBLIC DEBUG_TIMING)
endif()
if(ENABLE_DEBUG_LOGGING)
    target_compile_definitions(core_lib PUBLIC DEBUG_LOGGING)
endif()

# ── Server library ───────────────────────────────────────────────────────────
add_library(server_lib STATIC src/server/homplacing.cpp)
target_link_libraries(server_lib PUBLIC core_lib)

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