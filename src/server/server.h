#pragma once
#include "openfhe.h"
#include "core/context.h"

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


namespace Server {
    using namespace lbcrypto;
    using namespace Context;

    /**
     * @brief Create L and I matrices and run algorithm 2 for each user
     * 
     * @tparam T DCRTPoly
     * @tparam K Number of bins
     * @param cc Crypto Context (RGSW capable)
     * @param N number of users
     * @return std::vector<Ciphertext<T>> 
     */
    template <typename T = DCRTPoly, std::size_t K = 3>
    std::vector<Ciphertext<T>> Write(
        const ExtendedCryptoContext<T>& cc,
        const uint32_t N
    )
    {
        std::vector<Ciphertext<T>> hasWritten;
        hasWritten.reserve(N);

        std::vector<std::array<Ciphertext<T>, K>> L(N); // 3 x N
        std::vector<std::array<Ciphertext<T>, K>> I(N); // 3 x N

        

        return hasWritten;
    }

    // inline void HomPlacingSingleUser() { /* 1 user */ }
}