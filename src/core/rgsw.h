#pragma once
#include "pke/ciphertext-fwd.h"

template <typename T>
using RGSWCiphertext = std::vector<lbcrypto::Ciphertext<T>>;
