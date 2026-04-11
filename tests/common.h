/**
 * This file contains helpers used by most tests
 */
#pragma once

#include "openfhe.h"
#include <gtest/gtest.h>

#include <vector>

/// @brief Print a list of ciphertexts 
template <typename CC, typename T>
inline void PrintRGSW(
    const CC& cc, 
    const lbcrypto::KeyPair<T> keys, 
    const std::vector<lbcrypto::Ciphertext<T>>& vec, 
    size_t columns
) {
    lbcrypto::Plaintext plaintext;
    for(const auto &c : vec) {
        cc->Decrypt(keys.secretKey, c, &plaintext);
        plaintext->SetLength(columns);
        std::cout << plaintext << std::endl;
    }
}