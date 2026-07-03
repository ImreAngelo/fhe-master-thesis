/**
 * @file common.h
 * @brief This file contains helpers used by all the tests
 */
#pragma once

#include "openfhe.h"
#include <gtest/gtest.h>

// DEBUG_TIMING / DEBUG_LOGGING are opt-in via `DEBUG=1 make test-<name>`,
// which configures core with PUBLIC compile defs that also reach tests.
#include "core/utils/logging.h"
#include "core/utils/timer.h"

// Shared parameter presets (lives in shared/, reached via spar_shared INTERFACE target).
#include "params.h"

// Tests freely reference scheme symbols (ExtendedContext, GenContextBV, ...) unqualified.
using namespace core;
