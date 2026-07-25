/**
 * @file common.h
 * @brief This file contains helpers used by all the tests
 */
#pragma once

#include "openfhe.h"
#include <gtest/gtest.h>

// DEBUG_TIMING / DEBUG_LOGGING are opt-in via `DEBUG=1 make test-<name>`,
// which configures spar_utils with PUBLIC compile defs that also reach tests.
#include "spar/logging.h"
#include "spar/timer.h"

// Crypto parameters, loaded at runtime from params.toml at the repo root.
#include "spar/keys.h"
#include "spar/params.h"

// Tests freely reference scheme symbols (ExtendedContext, GenContextBV, ...) unqualified.
using namespace core;
