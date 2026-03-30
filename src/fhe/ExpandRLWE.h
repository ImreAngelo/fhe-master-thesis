#pragma once
#include "openfhe.h"

#include <cstdint>
#include <map>
#include <vector>

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
     * @brief Automorphism indices required by ExpandRLWE (Algorithm 3).
     *
     * At level lev, the automorphism exponent is k = n/2^lev + 1.
     * These are always odd (suitable for power-of-2 cyclotomic rings).
     *
     * Usage: generate keys before calling ExpandRLWE:
     *   auto indices = Server::ExpandRLWEAutoIndices(n, log_n);
     *   auto keys    = cc->EvalAutomorphismKeyGen(sk, indices);
     */
    inline std::vector<uint32_t> ExpandRLWEAutoIndices(uint32_t n, uint32_t log_n)
    {
        std::vector<uint32_t> indices;
        indices.reserve(log_n);
        for (uint32_t lev = 0; lev < log_n; lev++)
            indices.push_back(n / (1u << lev) + 1);
        return indices;
    }

    /**
     * @brief RLWE Expansion SubRoutine (Algorithm 3, Onion Ring ORAM).
     *
     * Expands a single RLWE ciphertext encrypting a polynomial with binary
     * coefficients into n individual ciphertexts, one per coefficient.
     *
     *   Input:  c = RLWE( sum_{i=0}^{n-1}  b_i * X^i ),   b_i in {0,1}
     *   Output: c_i = RLWE( n * b_i ),                     0 <= i < n
     *
     * Uses log(n) rounds of binary splitting.  At each level the
     * Subs(c_b, k) operation is realised by OpenFHE's EvalAutomorphism,
     * which applies the ring automorphism  X -> X^k  and key-switches
     * back to the original secret.
     *
     * @param cc        CryptoContext (BGV-RNS with DCRTPoly)
     * @param rlwe      The packed ciphertext to expand
     * @param log_n     log2(ring dimension)
     * @param autoKeys  Automorphism eval-key map from EvalAutomorphismKeyGen
     *                  (must contain keys for all indices from ExpandRLWEAutoIndices)
     */
    template <typename Element>
    CTVec<Element> ExpandRLWE(
        const CC<Element>&                           cc,
        const CT<Element>&                           rlwe,
        uint32_t                                     log_n,
        const std::map<uint32_t, EvalKey<Element>>&  autoKeys)
    {
        const uint32_t n = 1u << log_n;

        CTVec<Element> c(n);
        c[0] = rlwe;

        for (uint32_t lev = 0; lev < log_n; lev++)
        {
            const uint32_t k      = n / (1u << lev) + 1;
            const uint32_t stride = 1u << lev;   // active ciphertexts at this level

            // ── Build X^{-k} as a coef-packed plaintext ──────────────────────
            //
            // In Z[X]/(X^n + 1):
            //   X^{-k} = X^{2n - k}  mod (X^n + 1)
            //
            //   if (2n - k) <  n  → coeff +1 at position (2n - k)
            //   if (2n - k) >= n  → coeff -1 at position (n - k)
            //                       because X^n = -1 in the ring
            //
            std::vector<int64_t> xnk_coeffs(n, 0);
            const uint32_t pos = (2 * n - k) % (2 * n);
            if (pos < n)
                xnk_coeffs[pos] = 1;
            else
                xnk_coeffs[pos - n] = -1;

            Plaintext xnk = cc->MakeCoefPackedPlaintext(xnk_coeffs);

            // ── Split each active slot into even/odd children ────────────────
            //
            // Process in reverse so that c[b] is read before c[2b] overwrites it.
            //
            for (int32_t b = static_cast<int32_t>(stride) - 1; b >= 0; --b)
            {
                // Subs(c_b, k) = automorphism X → X^k  +  key-switch back to s
                CT<Element> sub = cc->EvalAutomorphism(c[b], k, autoKeys);

                // Even: c[2b] = c_b + Subs(c_b, k)
                c[2 * b] = cc->EvalAdd(c[b], sub);

                // Odd:  c[2b+1] = (c_b − Subs(c_b, k)) · X^{−k}
                CT<Element> diff = cc->EvalSub(c[b], sub);
                c[2 * b + 1]    = cc->EvalMult(diff, xnk);
            }
        }

        return c;
    }
}
