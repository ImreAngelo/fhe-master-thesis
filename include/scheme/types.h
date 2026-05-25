#pragma once
#include "openfhe.h"
#include <vector>

namespace spar {

using Poly = lbcrypto::DCRTPoly;
using CryptoContext = lbcrypto::CryptoContext<Poly>;
using PrivateKey = lbcrypto::PrivateKey<Poly>;
using PublicKey = lbcrypto::PublicKey<Poly>;
using Plaintext = lbcrypto::Plaintext;
using RLWE = lbcrypto::Ciphertext<Poly>;
using RGSW = std::vector<RLWE>;

using NativeInteger = lbcrypto::NativeInteger;
using NativeVector = std::vector<NativeInteger>;
// using BasicInteger = uint64_t;

// TODO: Check implementation for BFV
template <typename T>
using CCParams = lbcrypto::CCParams<T>;
using CryptoContextBGVRNS = lbcrypto::CryptoContextBGVRNS;

} // namespace spar
