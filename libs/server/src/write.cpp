#include "server/write.h"
#include "core/types.h"
#include "core/utils/logging.h"
#include "core/utils/noise.h"

namespace spar::server {
using namespace core;

template <uint32_t K, uint32_t D>
RGSW Write(const ExtendedContext& cc, const PublicKey& pk, const RLWE& Vr, const uint32_t n, Matrix<RLWE, K>& L, Matrix<RGSW, K>& I,
           const std::vector<std::vector<RGSW>>& z, const PrivateKey& debug_sk) {
    if (L.size() != n || I.size() != n) { throw std::logic_error("Incorrect state dimensions"); }
    if (z.size() != D) { throw std::logic_error("Incorrect number of choice vectors"); }
    if (z[0].size() != n) { throw std::logic_error("Incorrect number of encrypted bits"); }

    auto notHasWritten = cc->MakePublicRGSW(pk, cc->MakeCoefPackedPlaintext({1}));

    // TODO: The K first users can skip some iterations
    for (uint32_t d = 0; d < D; d++) {
        for (uint32_t k = 0; k < K; k++) {
            for (uint32_t i = 0; i < n; i++) {
                auto lhs = cc->EvalInternalProduct(I[i][k], notHasWritten);
                auto h = cc->EvalInternalProduct(lhs, z[d][i]);
                auto w = cc->EvalExternalProduct(Vr, h);

                // Update states
                L[i][k] = cc->EvalAdd(L[i][k], w);
                I[i][k] = cc->EvalSubRGSW(I[i][k], h);

                notHasWritten = cc->EvalSubRGSW(notHasWritten, h);
            }
        }
    }

    return notHasWritten;
}

// We always use K = D = 3
// TODO: Make compilation variable instead of template
template RGSW Write<3, 3>(const ExtendedContext&, const PublicKey&, const RLWE&, const uint32_t, Matrix<RLWE, 3>&, Matrix<RGSW, 3>&,
                          const std::vector<std::vector<RGSW>>&, const PrivateKey&);

}  // namespace spar::server
