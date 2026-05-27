/**
 * @file common.h
 * @brief This file contains helpers used by all the tests
 */
#pragma once

#include <gtest/gtest.h>
#include "openfhe.h"

// DEBUG_TIMING / DEBUG_LOGGING are opt-in via `DEBUG=1 make test-<name>`,
// which configures spar with PUBLIC compile defs that also reach tests.
#include "utils/timer.h"
#include "utils/logging.h"

// Shared parameter presets (lives in shared/, reached via spar_shared INTERFACE target).
#include "params.h"
