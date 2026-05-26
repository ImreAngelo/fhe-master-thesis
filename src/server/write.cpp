#include "server/write.h"
#include "utils/logging.h"

namespace spar::server {

template <uint32_t K, uint32_t D>
RGSW Write(const ExtendedContext& cc, const PublicKey& pk, const Plaintext& Vr, const uint32_t n,
                            ServerMatrix<RGSW, K>& L, ServerMatrix<RGSW, K>& I,
                            const std::vector<std::vector<RGSW>>& z)
{
    if(L.size() != n || I.size() != n) { throw std::logic_error("Incorrect state dimensions"); }
    if(z.size() != D) { throw std::logic_error("Incorrect number of choice vectors"); }
    if(z[0].size() != n) { throw std::logic_error("Incorrect number of encrypted bits"); }

    // // Debugging
    // const auto one = cc->Encrypt(pk, cc->MakeCoefPackedPlaintext({1}));
    // auto decrypt = [&](const RGSW& ct) {
    //     Plaintext pt;
    //     cc->Decrypt(debug_sk, cc->EvalExternalProduct(one, ct), &pt);
    //     pt->SetLength(1);
    //     return pt;
    // };

    auto notHasWritten = cc->EncryptRGSW(pk, cc->MakeCoefPackedPlaintext({1}));

    // TODO: The K first users can skip some iterations
    for(uint32_t d = 0; d < D; d++) {
        for(uint32_t k = 0; k < K; k++) {
            for(uint32_t i = 0; i < n; i++) {
                auto zI = cc->EvalInternalProduct(z[d][i], I[i][k]);
                auto h = cc->EvalInternalProduct(notHasWritten, zI);
                auto w = cc->EvalMultRGSW(h, Vr);

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
            }
        }
    }

    return notHasWritten;
}

// We always use K = D = 3
// TODO: Make compilation variable and use across project
template RGSW Write<3, 3>(const ExtendedContext&, const PublicKey&, const Plaintext&, const uint32_t,
                          ServerMatrix<RGSW, 3>&, ServerMatrix<RGSW, 3>&,
                          const std::vector<std::vector<RGSW>>&);

} // namespace spar::server
