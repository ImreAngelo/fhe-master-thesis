// #pragma once
// #include "openfhe.h"

// using namespace lbcrypto;

// // TODO: Global define
// template <typename T>
// using RGSWCiphertext = lbcrypto::Ciphertext<T>;

// class Server {

// public:
//     /**
//      * @brief Algorithm 2 from the sPAR paper (no external product).
//      *        Obliviously writes value into the first available slot among 3 candidate
//      *        bins. The server maintains data matrix L and availability matrix I (both
//      *        η × 3), which are updated in place.
//      *
//      * @return Encryption of hasWritten (1 if write succeeded, 0 otherwise)
//      */
//     std::vector<Ciphertext<DCRTPoly>> MultiHomPlacing(
//         const CryptoContext<DCRTPoly>&                cc,
//         const Ciphertext<DCRTPoly>&                   value,
//         const std::vector<RGSWCiphertext<DCRTPoly>>&  bits,
//         const uint64_t log_B,   // TODO: crypto param
//         const size_t ell        // TODO: crypto param
//     ) {
        
//     };
// }