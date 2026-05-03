/**
 * This file contains helpers used by multiple tests
 */
#pragma once

#include "openfhe.h"
#include <gtest/gtest.h>

// TODO: Define in cmake
// #define DEBUG

#if defined(DEBUG)
#define DEBUG_LOGGING
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