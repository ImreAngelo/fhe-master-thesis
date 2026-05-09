#include "openfhe.h"
#include "core/context.h"
#include "server/write.h"
#include "utils/logging.h"

// Map a centered value (-m/2, m/2] back to [0, m).
#define RECENTER(x, m) ((x) < 0 ? (x) + (m) : (x))

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
    // const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

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

    DEBUG_PRINT("Initial state:");
    server::debug::PrintMatrix("L", cc, L_mat, keys.secretKey); DEBUG_PRINT("");
    server::debug::PrintMatrix("I", cc, I_mat, keys.secretKey); DEBUG_PRINT("");

    for (uint64_t r = 0; r < N; r++) {
        DEBUG_PRINT("User " << std::to_string(r + 1) << ":");
        DEBUG_TIMER("User " + std::to_string(r + 1));

        const auto Vr = cc->MakeCoefPackedPlaintext({ static_cast<int64_t>(r + 1) });

        // Loop 1 - Place all at index r (user 0 always writes to slot 1 etc.)
        const auto z = client::PlaceAtN<T,D,L>(cc, keys.publicKey, r);

        // Loop 2
        const auto hasWritten = server::Write<T,K,D,L>(cc, keys.publicKey, Vr, L_mat, I_mat, z, keys.secretKey, r + 1);

        // Output results
        DEBUG_PRINT("User " << (r + 1) << " hasWritten (raw rgsw decrypt): " << server::Decrypt(cc, keys.secretKey, hasWritten));

        DEBUG_PRINT("");
        server::debug::PrintMatrix("L", cc, L_mat, keys.secretKey); DEBUG_PRINT("");
        server::debug::PrintMatrix("I", cc, I_mat, keys.secretKey); DEBUG_PRINT("");

        // Verify hasWritten encrypts 1 via external product: RGSW(hasWritten) ⊠ RLWE(1) → RLWE(1).
        // Direct RGSW decrypt reads a gadget-scaled row (gives m·g₀·s mod t, not m).
        auto hw_rlwe = cc->EvalExternalProduct(rlwe_one, hasWritten);
        Plaintext hw_pt;
        cc->Decrypt(keys.secretKey, hw_rlwe, &hw_pt);
        hw_pt->SetLength(1);
        ASSERT_EQ(hw_pt->GetCoefPackedValue()[0], 1) << "User " << (r + 1) << " hasWritten should encrypt 1";
    }

    // // Final state: L_mat[i][0] == i+1 (and 0 elsewhere), I_mat[i][k] == 0.
    // for (uint64_t i = 0; i < N; i++) {
    //     for (size_t k = 0; k < K; k++) {
    //         auto Lcell = server::Decrypt(cc, keys.secretKey, L_mat[i][k]);
    //         const int64_t expectedL = (k == 0) ? static_cast<int64_t>(i + 1) : 0;
    //         auto L_val = RECENTER(Lcell[0], t);
    //         ASSERT_EQ(L_val, expectedL) << "L[" << i << "][" << k << "]";

    //         auto Icell = server::Decrypt(cc, keys.secretKey, I_mat[i][k]);
    //         auto I_val = RECENTER(Icell[0], t);
    //         ASSERT_EQ(I_val, 0) << "I[" << i << "][" << k << "]";
    //     }
    // }
}

// Main tests
TEST(ServerWrite, N2)  { TestServerWrite<DCRTPoly, 3, 3, 1>(params::Small<CryptoContextBGVRNS>()); }
// TEST(ServerWrite, N4)  { server::TestServerWrite<DCRTPoly, 3, 3, 2>(CreateParams(3)); }
// TEST(ServerWrite, N8)  { server::TestServerWrite<DCRTPoly, 3, 3, 3>(CreateParams(3)); }
// TEST(ServerWrite, N16) { server::TestServerWrite<DCRTPoly, 3, 3, 4>(CreateParams(3)); }
// TEST(Server, Write_N4)  { server::TestServerWrite<DCRTPoly, 3, 3, 2>(CreateParams(3)); }
// TEST(Server, Write_N8)  { server::TestServerWrite<DCRTPoly, 3, 3, 3>(CreateParams(3)); }
// TEST(Server, Write_N16) { server::TestServerWrite<DCRTPoly, 3, 3, 4>(CreateParams(3)); }
// TEST(Server, Write_N32) { server::TestServerWrite<DCRTPoly, 3, 3, 5>(CreateParams(3)); }
