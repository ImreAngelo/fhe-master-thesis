#pragma once
#include "openfhe.h"
#include "core/context.h"
// TODO: Fix terrible include structure
#include "server/write.h"

// Map a centered value (-m/2, m/2] back to [0, m).
#define RECENTER(x, m) ((x) < 0 ? (x) + (m) : (x))

namespace server {
    using namespace lbcrypto;
    using namespace Context;

    /**
     * @brief Run sPAR Algorithm 2 (per-bin loops) for each user, then verify
     * the message landed at L_mat[r][0] = r+1 with hasWritten flipped to 1.
     *
     * Loop 1 (binary-tree demux of the chosen index) is collapsed at the client
     * to a one-hot RGSW vector to limit noise; the test sets all D choices to r,
     * so z[i][d] is RGSW(1) when i==r and RGSW(0) otherwise. Loop 2 runs
     * server-side fully in RGSW: internal product for z·I and the (1−hasWritten)
     * gate, plaintext × RGSW for the L update (Vr is encrypted under a different,
     * non-FHE scheme, so FHE never sees its semantic meaning), and RGSW add/sub
     * for the running L/I/hasWritten state.
     *
     * @tparam K Number of slots per bin
     * @tparam D Number of choices (default = A1, A2, A3)
     * @tparam L Bit-length of the address — N = 2^L users (and bins)
     */
    template <typename T = DCRTPoly, size_t K = 3, uint32_t D = 3, uint32_t L = 1>
    void TestServerWrite(const CCParams<CryptoContextRGSWBGV>& params)
    {
        auto cc = Context::GenExtendedCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        KeyPair<DCRTPoly> keys = cc->KeyGen();

        constexpr uint64_t N = (uint64_t(1) << L);
        const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

        const auto rgsw_zero = server::Encrypt(cc, keys.publicKey, cc->MakeCoefPackedPlaintext({ 0 }));
        const auto rgsw_one  = server::Encrypt(cc, keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        const auto rlwe_one  = cc->Encrypt(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));

        std::array<std::array<server::RGSWCiphertext<T>, K>, N> L_mat;
        std::array<std::array<server::RGSWCiphertext<T>, K>, N> I_mat;
        for (uint64_t i = 0; i < N; i++) {
            for (size_t k = 0; k < K; k++) {
                L_mat[i][k] = rgsw_zero;
                I_mat[i][k] = rgsw_one;
            }
        }

        for (uint64_t r = 0; r < N; r++) {
            DEBUG_PRINT("User " << std::to_string(r + 1) << ":");
            DEBUG_TIMER("User " + std::to_string(r + 1));

            const auto Vr = cc->MakeCoefPackedPlaintext({ static_cast<int64_t>(r + 1) });

            // Loop 1 - Place all at index r (user 0 always writes to slot 1 etc.)
            const auto z = client::PlaceAtN<T,D,L>(cc, keys.publicKey, r);

            // Loop 2
            const auto hasWritten = server::Write<T,K,D,L>(cc, keys.publicKey, Vr, L_mat, I_mat, z, keys.secretKey, r + 1);

            // Output results
            auto hw = server::Decrypt(cc, keys.secretKey, hasWritten, N);
            DEBUG_PRINT("User " << (r + 1) << " hasWritten: " << hw);

            for(const auto& ct : L_mat[r]) {
                auto cell = server::Decrypt(cc, keys.secretKey, ct);
                DEBUG_PRINT("L[" << r << "][0]: " << cell);
            }

            for(const auto& ct : I_mat[r]) {
                auto cell = server::Decrypt(cc, keys.secretKey, ct);
                DEBUG_PRINT("I[" << r << "]: " << cell);
            }

            // Verify hasWritten is correct for this user
            ASSERT_EQ(RECENTER(hw[0], t), 1);
        }

        // Final state: L_mat[i][0] == i+1 (and 0 elsewhere), I_mat[i][k] == 0.
        for (uint64_t i = 0; i < N; i++) {
            for (size_t k = 0; k < K; k++) {
                auto Lcell = server::Decrypt(cc, keys.secretKey, L_mat[i][k]);
                const int64_t expectedL = (k == 0) ? static_cast<int64_t>(i + 1) : 0;
                auto L_val = RECENTER(Lcell[0], t);
                ASSERT_EQ(L_val, expectedL) << "L[" << i << "][" << k << "]";

                auto Icell = server::Decrypt(cc, keys.secretKey, I_mat[i][k]);
                auto I_val = RECENTER(Icell[0], t);
                ASSERT_EQ(I_val, 0) << "I[" << i << "][" << k << "]";
            }
        }
    }
} // namespace server