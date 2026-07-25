/**
 * @file common.h
 * @brief Shared includes for every benchmark. Force-included by register_benchmark()
 *        in CMakeLists.txt, mirroring test/common.h.
 */
#pragma once

#include "openfhe.h"
#include <benchmark/benchmark.h>

#include "core/context.h"
#include "core/types.h"

// Crypto parameters, loaded at runtime from params.toml at the repo root.
#include "spar/keys.h"
#include "spar/params.h"

// Benchmarks freely reference scheme symbols (ExtendedContext, RGSW, RLWE, ...)
// unqualified, matching the convention in the server sources and the tests.
// This must be in scope before server/state.h and server/write.h are included,
// as those headers use core types unqualified.
using namespace core;
