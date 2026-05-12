#pragma once
#include "openfhe.h"
#include "core/include/context.h"
// TODO: Fix terrible include structure
#include "server/write.h"
#include "utils/logging.h"

// Map a centered value (-m/2, m/2] back to [0, m).
#define RECENTER(x, m) ((x) < 0 ? (x) + (m) : (x))

namespace server {
    using namespace lbcrypto;
    using namespace Context;

    /**
     * @brief Run sPAR Algorithm 2 (per-bin loops) for each user, then verify
     * the message landed at L_mat[r][0] = r+1 with hasWritten flipped to 1.
     *
     * @tparam K Number of slots per bin
     * @tparam D Number of choices (default = A1, A2, A3)
     * @tparam L Bit-length of the address — N = 2^L users (and bins)
     */
    template <typename T = DCRTPoly, size_t K = 3, uint32_t D = 3, uint32_t L = 1>
    void TestServerWrite(const CCParams<CryptoContextBGVRNS>& params)
    {
        auto cc = Context::GenExtendedCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        KeyPair<DCRTPoly> keys = cc->KeyGen();

        constexpr uint64_t N = (uint64_t(1) << L);

        const auto rgsw_zero = cc->EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 0 }));
        const auto rgsw_one  = cc->EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        const auto rlwe_one  = cc->Encrypt(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));

        std::array<std::array<server::RGSWCiphertext<T>, K>, N> L_mat;
        std::array<std::array<server::RGSWCiphertext<T>, K>, N> I_mat;
        for (uint64_t i = 0; i < N; i++) {
            for (size_t k = 0; k < K; k++) {
                L_mat[i][k] = cc->EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 0 }));
                I_mat[i][k] = cc->EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
            }
        }

        for (uint64_t r = 0; r < N; r++) {
            const auto Vr = cc->MakeCoefPackedPlaintext({ static_cast<int64_t>(r + 1) });

            // Loop 1 - Place all at index r (user 0 always writes to slot 1 etc.)
            const auto z = client::PlaceAtN<T,D,L>(cc, keys.publicKey, r);

            // Loop 2
            const auto hasWritten = server::Write<T,K,D,L>(cc, keys.publicKey, Vr, L_mat, I_mat, z, keys.secretKey, r + 1);

            // Output results
            DEBUG_PRINT(server::Decrypt(cc, keys.secretKey, hasWritten));
        }
    }
} // namespace server