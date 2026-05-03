/**
 * This file contains helpers used by multiple tests
 */
#pragma once

#include "openfhe.h"
#include <gtest/gtest.h>

// DEBUG_TIMING / DEBUG_LOGGING for test TUs. core_lib gets these via
// target_compile_definitions in the root CMakeLists.txt (which also propagates
// to dependents), so the timer macros fire in both context.cpp and tests.
#ifndef DEBUG_LOGGING
#define DEBUG_LOGGING
#endif
#ifndef DEBUG_TIMING
#define DEBUG_TIMING
#endif

#include "utils/timer.h"

/// @brief Print a list of RLWE ciphertexts 
template <typename CC, typename T>
inline void PrintRGSW(
    const CC& cc, 
    const lbcrypto::KeyPair<T> keys, 
    const std::vector<lbcrypto::Ciphertext<T>>& vec, 
    size_t columns = 1
) {
    lbcrypto::Plaintext plaintext;
    for(const auto &c : vec) {
        cc->Decrypt(keys.secretKey, c, &plaintext);
        plaintext->SetLength(columns);
        std::cout << plaintext << std::endl;
    }
}