#pragma once
#include "openfhe.h"
#include "core/rgsw.h"
#include "core/context.h"

namespace Server 
{   
    using namespace lbcrypto;

    /**
     * @brief Algorithm 1 without external product. 
     *        Places value in the slot encoded in bits. 
     * 
     * @tparam Poly DCRTPoly
     * @param cc The crypto context 
     * @param value Encrypted value to ble placed in slot n
     * @param c The encrypted bits of n
     */
    template <typename Poly>
    std::vector<Ciphertext<Poly>> HomPlacingSingleRLWE(
        const CryptoContext<Poly>&          cc,
        const Ciphertext<Poly>&             value,
        const std::vector<Ciphertext<Poly>> c
    )
    {
        using RLWE = Ciphertext<Poly>;
        using Vec = std::vector<Ciphertext<Poly>>;

        // Levels in tree L = log(n)
        const uint32_t L = c.size();
        const uint32_t n = 1u << L;

        // Initialize b = { V_r, 0, 0, ..., 0 }
        Vec b(2*n - 1);
        b[0] = value;

        for(uint32_t i = 0; i < L; i++) 
        {
            const RLWE& bit = c[i];

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
        Vec leaves(n);
        for(uint32_t i = 0; i < n; i++)
            leaves[i] = b[n - 1 + i];

        return leaves;
    }
}