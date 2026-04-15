#pragma once

#include "openfhe.h"
#include <cassert>
#include <vector>

namespace Server {
    using namespace lbcrypto;

    /**
     * @brief Computes the external product RGSW(μ) ⊡ RLWE(v) = RLWE(μ · v).
     *
     * Expects the RGSW ciphertext in the layout produced by Client::CreateRGSW_NegS:
     *
     *   rgsw[k]      (k = 0 .. ell-1) = Enc( μ · (−s) · B^{−(k+1)} )   [top half]
     *   rgsw[k+ell]  (k = 0 .. ell-1) = Enc( μ ·       B^{−(k+1)} )   [bottom half]
     *
     * Derivation (using gadget level k = 0):
     *   B · rgsw[ell]  =  B · Enc(μ · B^{−1})  =  Enc(μ)
     *   EvalMult(RLWE(v), Enc(μ))  =  RLWE(μ · v)
     *
     * Level k = 0 is used because higher levels amplify the RGSW encryption
     * noise by B^{k+1}, making k = 0 the lowest-noise choice.
     *
     * @param cc   CryptoContext — must have a relinearisation key registered via
     *             EvalMultKeyGen before calling this function.
     * @param rgsw RGSW(μ): 2·ell RLWE ciphertexts (rgsw.size() must equal 2·ell).
     * @param rlwe RLWE(v): the ciphertext to multiply.
     * @param ell  Number of gadget levels.
     * @param B    Gadget base.
     * @return     RLWE(μ · v)
     */
    template <typename T>
    Ciphertext<T> EvalExternalProduct(
        const CryptoContext<T>&           cc,
        const std::vector<Ciphertext<T>>& rgsw,
        const Ciphertext<T>&              rlwe,
        uint32_t                          ell,
        uint64_t                          B
    ) {
        assert(rgsw.size() == 2 * static_cast<size_t>(ell));

        const uint32_t ring_dim = cc->GetRingDimension();

        // Scale the first bottom-half row by the gadget base:
        //   rgsw[ell] = Enc(μ · B^{-1})  →  B · rgsw[ell] ≈ Enc(μ)
        auto pt_B = cc->MakePackedPlaintext(
            std::vector<int64_t>(ring_dim, static_cast<int64_t>(B)));
        auto enc_mu = cc->EvalMult(rgsw[ell], pt_B);

        // Homomorphic multiplication: RLWE(v) · Enc(μ) = RLWE(μ · v)
        return cc->EvalMult(rlwe, enc_mu);
    }

} // namespace Server
