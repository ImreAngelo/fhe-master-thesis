#pragma once
#include "openfhe.h"

namespace Server 
{
    using namespace lbcrypto;
    
    template <typename Element>
    using CC = CryptoContext<Element>;

    template <typename Element>
    using CT = Ciphertext<Element>;

    template <typename Element>
    using CTVec = std::vector<Ciphertext<Element>>;

    /**
     * @brief Algorithm 1 without external product. Places value in the slot encoded in bits. 
     * @tparam Element DCRTPoly
     * @param cc The crypto context 
     * @param value Encrypted value to ble placed in slot n
     * @param c The encrypted bits of n
     */
    template <typename Element>
    CTVec<Element> HomPlacingNoExt(
        const CC<Element>&      cc,
        const CT<Element>&      value,
        const CTVec<Element>    c
    )
    {
        // Levels in tree L = log(n)
        const uint32_t L = c.size();
        const uint32_t n = 1u << L;

        // Initialize b = { V_r, 0, 0, ..., 0 }
        CTVec<Element> b(2*n - 1);
        b[0] = value;

        for(uint32_t i = 0; i < L; i++) 
        {
            const CT<Element>& bit = c[i];

            // Iterate over all nodes in i-th level
            for(uint32_t j = 0; j < (1u << i); j++)
            {
                const uint32_t idx_right = (1u << (i + 1)) + 2*j;
                const uint32_t idx_left = idx_right - 1;

                const auto& parent = b[(1u << i) - 1 + j];

                b[idx_right] = cc->EvalMult(parent, bit);
                b[idx_left] = cc->EvalSub(parent, b[idx_right]);
            }
        }

        // Output last n nodes 
        CTVec<Element> leaves(n);
        for(uint32_t i = 0; i < n; i++)
            leaves[i] = b[n - 1 + i];

        return leaves;
    }

    /**
     * @brief Algorithm 2 from the sPAR paper (no external product).
     *        Obliviously writes value into the first available slot among 3 candidate
     *        bins. The server maintains data matrix L and availability matrix I (both
     *        η × 3), which are updated in place.
     *
     * @tparam Element DCRTPoly
     * @param cc         The crypto context
     * @param value      Encrypted value V_r to write
     * @param A          A[d][i]: encrypted bits of the d-th candidate address (d ∈ {0,1,2})
     * @param dataMatrix dataMatrix[i][k] = L_{i,k}: server data matrix (η × 3), modified in place
     * @param availMatrix availMatrix[i][k] = I_{i,k}: server availability matrix (η × 3), modified in place
     * @return           Encryption of hasWritten (1 if write succeeded, 0 otherwise)
     */
    template <typename Element>
    CT<Element> HomPlacingStarNoExt(
        const CC<Element>&                  cc,
        const CT<Element>&                  value,
        const std::vector<CTVec<Element>>&  A,
        std::vector<CTVec<Element>>&        dataMatrix,
        std::vector<CTVec<Element>>&        availMatrix
    )
    {
        const uint32_t L   = A[0].size();    // bits per address
        const uint32_t eta = 1u << L;        // number of bins
        constexpr uint32_t D = 3;            // number of candidate addresses
        constexpr uint32_t K = 3;            // slots per bin

        // Derive ct_zero and pt_one for arithmetic on plaintext constants
        auto ct_zero = cc->EvalSub(A[0][0], A[0][0]);
        auto pt_one  = cc->MakePackedPlaintext(std::vector<int64_t>{1});

        // Helper: compute 1 - ct  (EvalSub only does CT - PT, not PT - CT)
        auto one_minus = [&](const CT<Element>& ct) {
            return cc->EvalAdd(cc->EvalNegate(ct), pt_one);
        };

        // --- Phase 1 ---
        // For each candidate address d, run the HomPlacing tree with root = 1
        // to produce a one-hot indicator vector z[d] of length eta.
        std::vector<CTVec<Element>> z(D, CTVec<Element>(eta));

        for (uint32_t d = 0; d < D; d++)
        {
            const CTVec<Element>& bits = A[d];

            CTVec<Element> b(2 * eta - 1);
            b[0] = cc->EvalAdd(ct_zero, pt_one);  // b_0 = enc(1)

            for (uint32_t i = 0; i < L; i++)
            {
                const CT<Element>& bit = bits[i];

                for (uint32_t j = 0; j < (1u << i); j++)
                {
                    const uint32_t idx_right = (1u << (i + 1)) + 2 * j;
                    const uint32_t idx_left  = idx_right - 1;

                    const auto& parent = b[(1u << i) - 1 + j];

                    b[idx_right] = cc->EvalMult(parent, bit);
                    b[idx_left]  = cc->EvalSub(parent, b[idx_right]);
                }
            }

            for (uint32_t i = 0; i < eta; i++)
                z[d][i] = b[eta - 1 + i];
        }

        // --- Phase 2 ---
        // Obliviously write value into the first available slot.
        // h = z[d][i] * I[i][k] * (1 - hasWritten) gates each write.
        auto hasWritten = ct_zero;

        for (uint32_t d = 0; d < D; d++)
        {
            for (uint32_t k = 0; k < K; k++)
            {
                for (uint32_t i = 0; i < eta; i++)
                {
                    auto h = cc->EvalMult(z[d][i], availMatrix[i][k]);
                    h      = cc->EvalMult(h, one_minus(hasWritten));

                    // L[i][k] += h * value
                    dataMatrix[i][k]  = cc->EvalAdd(dataMatrix[i][k],
                                                     cc->EvalMult(h, value));
                    // I[i][k] -= h
                    availMatrix[i][k] = cc->EvalSub(availMatrix[i][k], h);

                    // hasWritten += h
                    hasWritten = cc->EvalAdd(hasWritten, h);
                }
            }
        }

        return hasWritten;
    }
}