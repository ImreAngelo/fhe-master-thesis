/**
 * This file contains helpers used by most tests
 */
#pragma once

#include <gtest/gtest.h>
#include "openfhe.h"
#include <vector>

template <typename T>
inline void PrintRGSW(
    const lbcrypto::CryptoContext<T>& cc, 
    const lbcrypto::KeyPair<T> keys, 
    const std::vector<lbcrypto::Ciphertext<T>>& vec, size_t columns
) {
    lbcrypto::Plaintext plaintext;
    for(const auto &c : vec) {
        cc->Decrypt(keys.secretKey, c, &plaintext);
        plaintext->SetLength(columns);
        std::cout << plaintext << std::endl;
    }
}