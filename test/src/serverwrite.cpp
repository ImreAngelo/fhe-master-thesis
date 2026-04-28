#include "openfhe.h"
#include "core/context.h"
#include <bitset>

using namespace lbcrypto;
using namespace Context;

// TODO: Overload EvalAdd and EvalSub in context.h/cpp with RGSW lhs and rhs
template <typename T>
inline RGSWCiphertext<T> AddRGSW(
    const Context::ExtendedCryptoContext<T>& cc,
    const RGSWCiphertext<T>& A,
    const RGSWCiphertext<T>& B)
{
    RGSWCiphertext<T> out(A.size());
    for (size_t i = 0; i < A.size(); i++)
        out[i] = cc->EvalAdd(A[i], B[i]);
    return out;
}

template <typename T>
inline RGSWCiphertext<T> SubRGSW(
    const Context::ExtendedCryptoContext<T>& cc,
    const RGSWCiphertext<T>& A,
    const RGSWCiphertext<T>& B)
{
    RGSWCiphertext<T> out(A.size());
    for (size_t i = 0; i < A.size(); i++)
        out[i] = cc->EvalSub(A[i], B[i]);
    return out;
}


/**
 * @brief Create L and I matrices and run algorithm 2 for each user
 * Run loop 1 on client side to limit noise and verify correctness
 * 
 * @tparam T DCRTPoly
 * @tparam K Number of slots per bin
 * @tparam D Number of choices (default = A1, A2, A3)
 * 
 * @param cc Crypto Context (RGSW capable)
 * @param L number of bits -> N = 2^L users (and bins)
 * @return std::vector<Ciphertext<T>> 
 */
template <typename T = DCRTPoly, size_t K = 3, uint32_t D = 3, uint32_t L>
// std::vector<RGSWCiphertext<T>> 
void TestServerWrite(
    const CCParams<CryptoContextRGSWBGV>& params
    // const uint32_t L
)
{
    // Set up OpenFHE
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Algorithm 2 variables
    constexpr uint64_t N = (uint64_t(1) << L);
    // std::vector<RGSWCiphertext<T>> hasWritten(N, cc->EncryptRGSW(keys.publicKey, { 0 }));
    
    // Set up variables maintained by server
    std::array<Ciphertext<T>, K> L_mat; // K x N
    std::array<Ciphertext<T>, K> I_mat; // K x N

    const auto ones = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 1)));
    const auto zero = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 0)));
    
    // initialize L = 0, I = 1
    for(size_t k = 0; k < K; k++) {
        L_mat[k] = zero;
        I_mat[k] = ones;
    }

    // Repeat for each user
    for(uint64_t r = 0; r < N; r++) {
        DEBUG_TIMER("User " + std::to_string(r + 1));
        
        std::cout << "User " << (r + 1) << ":" << std::endl;

        // Set up dummy value and A_j = {r, r, r} choices
        // const auto pt = cc->MakePackedPlaintext({static_cast<int64_t>(r + 1)});
        const auto Vr = cc->EncryptRGSW(keys.publicKey, {static_cast<int64_t>(r + 1)});
        
        // Initialize z matrix (n slots)
        std::array<RGSWCiphertext<T>, D> z;
        
        // Run loop 1 on client-side to limit noise!
        for(uint32_t d = 0; d < D; d++) {
            std::vector<int64_t> b(N);
            b[r] = 1;
            z[d] = cc->EncryptRGSW(keys.publicKey, b);

            std::cout << "z[" << r << "][" << d << "]: " << b << std::endl;

            // auto rlwe = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(b));
            // auto extp = cc->EvalExternalProduct(rlwe, z[d]);
            // Plaintext pt;
            // cc->Decrypt(keys.secretKey, extp, &pt);
            // pt->SetLength(N);

            // std::cout << "z[" << r << "][" << d << "]: " << pt->GetPackedValue() << std::endl;
        }
    
        // We are done with parsing the indices sent by the client. We want to place the value in the first available empty slot. //
        // const auto one = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 1)));
        
        // Run loop 2 on server
        auto hasWritten = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>(N, 0)));
        for(uint32_t d = 0; d < D; d++) {
            for(uint32_t k = 0; k < K; k++) { // number of slots in each bin //
                auto zI  = cc->EvalExternalProduct(I_mat[k], z[d]);
                auto sub = cc->EvalSub(ones, hasWritten);
                auto h   = cc->EvalMult(zI, sub);
                
                L_mat[k] = cc->EvalAdd(L_mat[k], cc->EvalExternalProduct(h, Vr));
                I_mat[k] = cc->EvalSub(I_mat[k], h);

                hasWritten = cc->EvalAdd(hasWritten, h);
            }
        }

        // Output success message
        // PrintRGSW(cc, keys, hasWritten, N);
        
        Plaintext hasWrittenPt;
        cc->Decrypt(keys.secretKey, hasWritten, &hasWrittenPt);
        hasWrittenPt->SetLength(N);
        std::cout << "User " << (r + 1) << " has written: " << hasWrittenPt << std::endl;
    }

    // return hasWritten;
}

CCParams<CryptoContextRGSWBGV> CreateParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(4);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);
    params.SetScalingTechnique(FIXEDAUTO);
    params.SetGadgetBase(30);               // NOTE: base = 2^base
    params.SetGadgetDecomposition(7);       // TODO: set automatically
    return params;
}

TEST(Server, Write) { 
    const auto& params = CreateParams();
    TestServerWrite<DCRTPoly, 3, 1, 1>(params); 
}



// std::cout << "z[" << r << "][" << d << "]:\t[";
// for(uint32_t i = 0; i < N; i++) {
//     const auto idx = uint32_t(1) << (L - 1);
//     const auto bit = b[idx - 1 + i];
//     z[i][d] = cc->EncryptRGSW(keys.publicKey, { bit });

//     // const auto ct = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit}));
//     // const auto ct = cc->EncryptRGSW(keys.publicKey, {bit});
//     // z[i][d] = cc->EvalAdd(z[i][d], ct);
    
//     // std::cout << idx - 1 + i << ": " << b[idx - 1 + i] << " / " << (2*N - 2) << " (" << b.size() << ")" << std::endl;
    
//     // Print row
//     // Plaintext decrypted;
//     // cc->Decrypt(keys.secretKey, z[i][d], &decrypted);
//     // std::cout << decrypted->GetPackedValue()[0] << ((i < N - 1) ? ", " : "]");
//     // PrintRGSW(cc, keys, z[i][d], 1);

//     Plaintext decrypted;
//     auto rlwe = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit}));
//     cc->Decrypt(keys.secretKey, cc->EvalExternalProduct(rlwe, z[i][d]), &decrypted);
//     decrypted->SetLength(1);
//     std::cout << decrypted->GetPackedValue()[0] << ((i < N - 1) ? ", " : "]");
// }
// std::cout << std::endl;