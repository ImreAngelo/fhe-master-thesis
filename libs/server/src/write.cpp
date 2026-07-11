#include "server/write.h"
#include "core/utils/logging.h"
#include "core/utils/noise.h"

namespace spar::server {
using namespace core;

template <uint32_t K, uint32_t D>
RGSW Write(const ExtendedContext& cc, const PublicKey& pk, const Plaintext& Vr, const uint32_t n, Matrix<K>& L, Matrix<K>& I,
           const std::vector<std::vector<RGSW>>& z, const PrivateKey& debug_sk) {
    if (L.size() != n || I.size() != n) {
        throw std::logic_error("Incorrect state dimensions");
    }
    if (z.size() != D) {
        throw std::logic_error("Incorrect number of choice vectors");
    }
    if (z[0].size() != n) {
        throw std::logic_error("Incorrect number of encrypted bits");
    }

    // // Debugging
    // const auto one = cc->Encrypt(pk, cc->MakeCoefPackedPlaintext({1}));
    // auto decrypt = [&](const RGSW& ct) {
    //     Plaintext pt;
    //     cc->Decrypt(debug_sk, cc->EvalExternalProduct(one, ct), &pt);
    //     pt->SetLength(1);
    //     return pt;
    // };

    auto notHasWritten = cc->EncryptRGSW(pk, cc->MakeCoefPackedPlaintext({1}));

    if (debug_sk) {
        DEBUG_PRINT("log2(Q) = " << cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB());
        PRINT_MAX_NOISE_MSB(cc, notHasWritten[0], debug_sk);  // fresh RGSW baseline
    }

    // TODO: The K first users can skip some iterations
    for (uint32_t d = 0; d < D; d++) {
        for (uint32_t k = 0; k < K; k++) {
            for (uint32_t i = 0; i < n; i++) {
                auto zI = cc->EvalInternalProduct(z[d][i], I[i][k]);
                auto h = cc->EvalInternalProduct(notHasWritten, zI);
                auto w = cc->EvalMultRGSW(h, Vr);

                if (debug_sk) {
                    DEBUG_PRINT("--- d=" << d << " k=" << k << " i=" << i << " ---");
                    PRINT_MAX_NOISE_MSB(cc, I[i][k][0], debug_sk);  // state going into product 1 (rhs!)
                    PRINT_MAX_NOISE_MSB(cc, zI[0], debug_sk);       // after product 1
                    PRINT_MAX_NOISE_MSB(cc, h[0], debug_sk);        // after product 2 (zI on rhs!)
                    PRINT_MAX_NOISE_MSB(cc, w[0], debug_sk);        // after plaintext mult by Vr
                }

                // DEBUG_PRINT("Available and asking?\t" << decrypt(zI));
                // DEBUG_PRINT("Can write?\t\t" << decrypt(notHasWritten));
                // DEBUG_PRINT("Will write?\t\t" << decrypt(h));
                // DEBUG_PRINT("Writing value:\t" << decrypt(w));
                // DEBUG_PRINT("L = " << decrypt(L[i][k]) << "\t -> " << decrypt(cc->EvalAddRGSW(L[i][k], w)));
                // DEBUG_PRINT("I = " << decrypt(I[i][k]) << "\t -> " << decrypt(cc->EvalSubRGSW(L[i][k], h)));
                // DEBUG_PRINT("");

                // Update states
                L[i][k] = cc->EvalAddRGSW(L[i][k], w);
                I[i][k] = cc->EvalSubRGSW(I[i][k], h);

                notHasWritten = cc->EvalSubRGSW(notHasWritten, h);

                if (debug_sk) {
                    PRINT_MAX_NOISE_MSB(cc, L[i][k][0], debug_sk);          // accumulated write state
                    PRINT_MAX_NOISE_MSB(cc, I[i][k][0], debug_sk);          // updated slot state
                    PRINT_MAX_NOISE_MSB(cc, notHasWritten[0], debug_sk);    // updated flag
                }
            }
        }
    }

    return notHasWritten;
}

// We always use K = D = 3
// TODO: Make compilation variable and use across project
template RGSW Write<3, 3>(const ExtendedContext&, const PublicKey&, const Plaintext&, const uint32_t, Matrix<3>&, Matrix<3>&,
                          const std::vector<std::vector<RGSW>>&, const PrivateKey&);

}  // namespace spar::server
