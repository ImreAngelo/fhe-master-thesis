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
}