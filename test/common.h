/**
 * This file contains helpers used by multiple tests
 */
#pragma once

#include "openfhe.h"
#include <gtest/gtest.h>

// DEBUG_TIMING / DEBUG_LOGGING are opt-in via `DEBUG=1 make test-<name>`,
// which configures core_lib with PUBLIC compile defs that also reach tests.
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