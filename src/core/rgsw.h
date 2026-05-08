#pragma once
#include "openfhe.h"

using namespace lbcrypto;

template <typename T = DCRTPoly>
struct RGSW {
    std::vector<Ciphertext<T>> rows;
};