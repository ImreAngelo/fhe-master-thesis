#include "openfhe.h"
#include "core/context.h"

using namespace lbcrypto;
using namespace Context;


/**
 * @brief Run sPAR Algorithm 2 for each user and verify hasWritten[r] == 1.
 *
 * Loop 1 (z = RGSW demux of the chosen index) is executed by the client to
 * limit noise — z[d] is encrypted directly as a one-hot vector. Loop 2 runs
 * server-side using:
 *   - external product (RLWE × RGSW)  for the I_mat[k] · z[d] pairing,
 *   - element-wise add/sub on RLWE     for the running L/I/hasWritten state.
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
    cc->EvalMultKeyGen(keys.secretKey);

    constexpr uint64_t N = (uint64_t(1) << L);

    std::array<Ciphertext<T>, K> L_mat;
    std::array<Ciphertext<T>, K> I_mat;

    const auto ones = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 1)));
    const auto zero = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 0)));

    for (size_t k = 0; k < K; k++) {
        L_mat[k] = zero;
        I_mat[k] = ones;
    }

    for (uint64_t r = 0; r < N; r++) {
        DEBUG_TIMER("User " + std::to_string(r + 1));
        DEBUG_PRINT("User " << std::to_string(r + 1) << ":");

        const auto Vr = cc->EncryptRGSW(keys.secretKey, { static_cast<int64_t>(r + 1) });

        // Loop 1: client-side one-hot encoding of the chosen index
        std::array<RGSWCiphertext<T>, D> z;
        for (uint32_t d = 0; d < D; d++) {
            std::vector<int64_t> b(N);
            b[r] = 1;
            z[d] = cc->EncryptRGSW(keys.secretKey, b);

            DEBUG_PRINT("z[" << r << "][" << d << "]: " << b);
        }

        // Loop 2: server-side write attempt across (D × K) (slot, bin) pairs
        auto hasWritten = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 0)));
        for (uint32_t d = 0; d < D; d++) {
            for (uint32_t k = 0; k < K; k++) {
                auto zI  = cc->EvalExternalProduct(I_mat[k], z[d]);
                auto sub = cc->EvalSub(ones, hasWritten);
                auto h   = cc->EvalMult(zI, sub);

                L_mat[k]   = cc->EvalAdd(L_mat[k], cc->EvalExternalProduct(h, Vr));
                I_mat[k]   = cc->EvalSub(I_mat[k], h);
                hasWritten = cc->EvalAdd(hasWritten, h);
            }
        }

        Plaintext hasWrittenPt;
        cc->Decrypt(keys.secretKey, hasWritten, &hasWrittenPt);
        hasWrittenPt->SetLength(N);

        DEBUG_PRINT("User " << (r + 1) << " has written: " << hasWrittenPt);

        const auto& values = hasWrittenPt->GetPackedValue();
        for (uint64_t i = 0; i < N; i++) {
            ASSERT_EQ(values[i], (i == r) ? 1 : 0);
        }
    }
}

inline CCParams<CryptoContextRGSWBGV> CreateParams(uint32_t depth) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);
    // params.SetRingDim(1 << 14); // 16384
    params.SetScalingTechnique(FIXEDAUTO);
    return params;
}

TEST(Server, Write_111) { TestServerWrite<DCRTPoly, 1, 1, 1>(CreateParams(4)); }
TEST(Server, Write_K2)  { TestServerWrite<DCRTPoly, 2, 1, 1>(CreateParams(4)); }
TEST(Server, Write_D2)  { TestServerWrite<DCRTPoly, 1, 2, 1>(CreateParams(8)); }
TEST(Server, Write_A2)  { TestServerWrite<DCRTPoly, 2, 2, 1>(CreateParams(8)); }

// GOAL: Pass this test!
TEST(ServerWrite, N2)  { TestServerWrite<DCRTPoly, 3, 3, 1>(CreateParams(12)); }
