#include "core/RGSW.h"
#include "math/nbtheory.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>

// Test B
#include "openfhe.h"
#include "core/include/params.h"
#include "core/include/context.h"

using namespace core;
using namespace lbcrypto;

// Centered difference mod Q: returns signed(a - b) in (-Q/2, Q/2]
static int64_t centeredDiff(uint64_t a, uint64_t b, uint64_t Q) {
    int64_t d = static_cast<int64_t>(a) - static_cast<int64_t>(b);
    if (d >  static_cast<int64_t>(Q / 2)) d -= static_cast<int64_t>(Q);
    if (d < -static_cast<int64_t>(Q / 2)) d += static_cast<int64_t>(Q);
    return d;
}

extern void TestA();
extern void TestB();

int main() {
    // TestA();
    TestB();
    return 0;
}

void TestB() {
    std::cout << "Running Test B" << std::endl;

    // Step 1: Set CryptoContext
    CCParams<CryptoContextRGSWBGV> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetGadgetBase(2);
    parameters.SetGadgetDigits(3);

    // auto Q = ... 
    // parameters.SetRGSWModulus(Q);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    
    // TODO: enable when supported by the scheme
    // cc->Enable(MULTIPARTY); 

    // DO NOT: Build RGSWParams from the same CCParams when needed:
    // DO NOT: auto rgswParams = RGSWParams::Make(params.GetRingDim(), Q, params.GetGadgetBase());

    // Step 2: Key Generation
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    // cc->RGSWSecretKeyGen(keyPair.secretKey); // TODO: Automorphism key for HomExpand ???

    // Step 3: Encryption
    Plaintext plaintext = cc->MakePackedPlaintext({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    auto rlweCiphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    auto rgswCiphertext = cc->EncryptRGSW(keyPair.publicKey, plaintext);
}


void TestA() {
    // -------------------------------------------------------------------------
    // Phase 1: Params sanity
    // -------------------------------------------------------------------------
    const uint32_t N     = 256;
    const uint32_t baseB = 2; // 1 << 3; // B = 8

    // LastPrime<NativeInteger>(bits, cyclotomic_order): largest prime p ≤ 2^bits
    // with p ≡ 1 (mod cyclotomic_order), required for NTT to exist.
    NativeInteger Q = LastPrime<NativeInteger>(27, 2 * N);

    auto p = RGSWParams::Make(N, Q, baseB);

    std::cout << "[Phase 1] Params:\n";
    std::cout << "  N       = " << p.N << "\n";
    std::cout << "  Q       = " << p.Q << "\n";
    std::cout << "  baseB   = " << p.baseB << "\n";
    std::cout << "  digitsG = " << p.digitsG << "\n";
    for (uint32_t j = 0; j < std::min(p.digitsG, 4u); ++j)
        std::cout << "  Gpower[" << j << "] = " << p.Gpower[j] << "\n";

    assert(p.Gpower[0] == NativeInteger(1));
    assert(p.Gpower[1] == NativeInteger(baseB));
    assert(p.digitsG == static_cast<uint32_t>(std::ceil(
        std::log2(Q.ConvertToDouble()) / std::log2(static_cast<double>(baseB)))));
    std::cout << "[Phase 1] PASSED\n\n";

    // -------------------------------------------------------------------------
    // Phase 2: RLWE round-trip
    // -------------------------------------------------------------------------
    NativePoly sk = RGSWKeyGen(p);

    NativeInteger scaling = p.Q >> 1; // Q/2  (represents plaintext bit 1)

    // Encrypt mu=1 (constant poly with coeff[0]=1, rest 0)
    NativePoly mu1(p.polyParams, Format::COEFFICIENT, true);
    mu1[0] = NativeInteger(1);

    RLWECt ct1 = RLWEEncrypt(p, sk, mu1, scaling);
    NativePoly dec1 = RLWEDecrypt(p, sk, ct1);

    uint64_t Qval  = p.Q.ConvertToInt<uint64_t>();
    uint64_t half  = scaling.ConvertToInt<uint64_t>();
    uint64_t d1c0  = dec1[0].ConvertToInt<uint64_t>();
    int64_t  diff1 = centeredDiff(d1c0, half, Qval);

    std::cout << "[Phase 2] RLWE(mu=1) decrypt coeff[0] = " << d1c0
              << "  (expected ~" << half << ", diff=" << diff1 << ")\n";
    assert(std::abs(diff1) < static_cast<int64_t>(Qval / 16));

    // Encrypt mu=0
    NativePoly mu0(p.polyParams, Format::COEFFICIENT, true);
    RLWECt ct0 = RLWEEncrypt(p, sk, mu0, scaling);
    NativePoly dec0 = RLWEDecrypt(p, sk, ct0);
    uint64_t d0c0   = dec0[0].ConvertToInt<uint64_t>();
    int64_t  diff0  = centeredDiff(d0c0, 0, Qval);

    std::cout << "[Phase 2] RLWE(mu=0) decrypt coeff[0] = " << d0c0
              << "  (expected ~0, diff=" << diff0 << ")\n";
    assert(std::abs(diff0) < static_cast<int64_t>(Qval / 16));

    std::cout << "[Phase 2] PASSED\n\n";

    // -------------------------------------------------------------------------
    // Phase 3: Gadget decomposition reconstruction
    // -------------------------------------------------------------------------
    auto dct = GadgetDecompose(p, ct1);
    assert(dct.size() == 2 * p.digitsG);

    // Reconstruct d0: sum_j  dct[2j][k] * Gpower[j]  should ≡ ct1.GetElements()[0][k]
    // We verify coefficient 0.
    // Need a COEFFICIENT copy of ct1[0]
    NativePoly ct1a = ct1.GetElements()[0];
    ct1a.SetFormat(Format::COEFFICIENT);
    uint64_t orig_k0 = ct1a[0].ConvertToInt<uint64_t>();

    uint64_t recon = 0;
    for (uint32_t j = 0; j < p.digitsG; ++j) {
        uint64_t digit = dct[2 * j + 0][0].ConvertToInt<uint64_t>();
        recon = (recon + digit * p.Gpower[j].ConvertToInt<uint64_t>()) % Qval;
    }

    std::cout << "[Phase 3] ct[0][0] original = " << orig_k0
              << "  reconstructed = " << recon << "\n";
    assert(recon == orig_k0);
    std::cout << "[Phase 3] PASSED\n\n";

    // -------------------------------------------------------------------------
    // Phase 4: RGSW encrypt + external product
    // -------------------------------------------------------------------------
    // C1 = RGSW(1):  C1 ⊡ ct1 should decrypt the same as ct1
    RGSWCt C1 = RGSWEncrypt(p, sk, mu1);
    RLWECt ep1 = ExternalProduct(p, C1, ct1);
    NativePoly decEp1 = RLWEDecrypt(p, sk, ep1);
    uint64_t ep1c0   = decEp1[0].ConvertToInt<uint64_t>();
    int64_t  diffEp1 = centeredDiff(ep1c0, half, Qval);

    std::cout << "[Phase 4] RGSW(1) ⊡ RLWE(1) decrypt coeff[0] = " << ep1c0
              << "  (expected ~" << half << ", diff=" << diffEp1 << ")\n";
    assert(std::abs(diffEp1) < static_cast<int64_t>(Qval / 8));

    // C0 = RGSW(0):  C0 ⊡ ct1 should decrypt to ~0
    RGSWCt C0 = RGSWEncrypt(p, sk, mu0);
    RLWECt ep0 = ExternalProduct(p, C0, ct1);
    NativePoly decEp0 = RLWEDecrypt(p, sk, ep0);
    uint64_t ep0c0   = decEp0[0].ConvertToInt<uint64_t>();
    int64_t  diffEp0 = centeredDiff(ep0c0, 0, Qval);

    std::cout << "[Phase 4] RGSW(0) * RLWE(1) decrypt coeff[0] = " << ep0c0
              << "  (expected ~0, diff=" << diffEp0 << ")\n";
    assert(std::abs(diffEp0) < static_cast<int64_t>(Qval / 8));

    std::cout << "[Phase 4] PASSED\n\n";

    // -------------------------------------------------------------------------
    // Phase 5: CMux
    // -------------------------------------------------------------------------
    // CMux(C1, d1=ct1, d0=ct0): selector=1 → should decrypt like ct1 (msg=1)
    RLWECt cmux1out = CMux(p, C1, ct1, ct0);
    NativePoly decCmux1 = RLWEDecrypt(p, sk, cmux1out);
    int64_t diffCmux1 = centeredDiff(decCmux1[0].ConvertToInt<uint64_t>(), half, Qval);
    std::cout << "[Phase 5] CMux(sel=1, d1=1, d0=0) coeff[0] = "
              << decCmux1[0] << "  (expected ~" << half << ", diff=" << diffCmux1 << ")\n";
    assert(std::abs(diffCmux1) < static_cast<int64_t>(Qval / 8));

    // CMux(C0, d1=ct1, d0=ct0): selector=0 → should decrypt like ct0 (msg=0)
    RLWECt cmux0out = CMux(p, C0, ct1, ct0);
    NativePoly decCmux0 = RLWEDecrypt(p, sk, cmux0out);
    int64_t diffCmux0 = centeredDiff(decCmux0[0].ConvertToInt<uint64_t>(), 0, Qval);
    std::cout << "[Phase 5] CMux(sel=0, d1=1, d0=0) coeff[0] = "
              << decCmux0[0] << "  (expected ~0, diff=" << diffCmux0 << ")\n";
    assert(std::abs(diffCmux0) < static_cast<int64_t>(Qval / 8));

    std::cout << "[Phase 5] PASSED\n\n";

    std::cout << "All tests passed.\n";
}