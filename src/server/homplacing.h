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
     * @tparam Element DCRTPoly
     * @param cc The crypto context 
     * @param value Encrypted value to ble placed in slot n
     * @param c The encrypted bits of n
     */
    template <typename Element>
    std::vector<Ciphertext<Element>> HomPlacingNoExt(
        const CryptoContext<Element>&          cc,
        const Ciphertext<Element>&             value,
        const std::vector<Ciphertext<Element>> c
    )
    {
        using RLWE = Ciphertext<Element>;
        using Vec = std::vector<Ciphertext<Element>>;

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

    /**
     * @brief Algorithm 1 without external product. 
     *        Places value in the slot encoded in bits. 
     * 
     * @tparam Element DCRTPoly
     * @param cc The crypto context 
     * @param value Encrypted value to ble placed in slot n
     * @param c The encrypted bits of n
     */
    std::vector<Ciphertext<DCRTPoly>> HomPlacing(
        const Context::ExtendedCryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>&                     value,
        const std::vector<RGSWCiphertext<DCRTPoly>>&    bits
    );

    /**
     * @brief Algorithm 2 from the sPAR paper.
     *
     * @param cc          Extended crypto context
     * @param publicKey   Common public key (used to initialize encrypted constants)
     * @param value       Encrypted value to be placed
     * @param A           D candidate addresses, each as L encrypted RGSW bits
     * @param L_matrix    Data matrix (η × K), mutated
     * @param I_matrix    Availability matrix (η × K), mutated
     * @return            Encryption of hasWritten (1 if a write succeeded, 0 otherwise)
     */
    RGSWCiphertext<DCRTPoly> MultiHomPlacing(
        const Context::ExtendedCryptoContext<DCRTPoly>&                  cc,
        const PublicKey<DCRTPoly>&                                       publicKey,
        const Ciphertext<DCRTPoly>&                                      value,
        const std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&        A,
        std::vector<std::vector<Ciphertext<DCRTPoly>>>&                  L_matrix,
        std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&              I_matrix
    );
}