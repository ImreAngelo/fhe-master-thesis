#pragma once
#include "openfhe.h"

/**
 * @file noise.h
 * @brief Checks the accumulated noise in an RLWE ciphertext in BGV
 */
namespace spar::utils {
inline lbcrypto::BigInteger MaxNoise(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
                                     const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                                     const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk) {
    using namespace lbcrypto;

    std::vector<DCRTPoly> cv = ct->GetElements();
    DCRTPoly s = sk->GetPrivateElement();

    // This should never happen
    if (cv[0].GetNumOfElements() < s.GetNumOfElements()) s.DropLastElements(s.GetNumOfElements() - cv[0].GetNumOfElements());

    DCRTPoly phase = cv[0];
    phase.SetFormat(Format::EVALUATION);

    DCRTPoly sPow = s;
    for (size_t i = 1; i < cv.size(); ++i) {
        cv[i].SetFormat(Format::EVALUATION);
        phase += cv[i] * sPow;
        if (i + 1 < cv.size()) sPow *= s;
    }

    phase.SetFormat(Format::COEFFICIENT);
    auto b = phase.CRTInterpolate();

    const BigInteger Q = b.GetModulus();
    const BigInteger halfQ = Q >> 1;

    // Decrypt the ciphertext to get the plaintext
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    NativePoly m = pt->GetElement<NativePoly>();
    m.SetFormat(Format::COEFFICIENT);
    const BigInteger t(sk->GetCryptoParameters()->GetPlaintextModulus());
    const BigInteger delta(ct->GetScalingFactorInt());  // 1 for FIXEDMANUAL

    BigInteger maxE(0);
    for (usint i = 0; i < b.GetLength(); ++i) {
        BigInteger mi = BigInteger(m[i].ConvertToInt<uint64_t>()).ModMul(delta, t);
        BigInteger d = b[i].ModSub(mi, Q);
        if (d > halfQ) d = Q - d;
        if (d > maxE) maxE = d;
    }

    return maxE;
}
}  // namespace spar::utils


#include "logging.h"
#include "record.h"

// Prints ||epsilon||_inf for a ciphertext. Args: crypto context, ciphertext,
// secret key. Prefixes the ciphertext expression so multiple prints are legible.
#define PRINT_MAX_NOISE(cc, ct, sk) DEBUG_PRINT("max noise [" #ct "] = " << spar::utils::MaxNoise((cc), (ct), (sk)))
#define PRINT_MAX_NOISE_MSB(cc, ct, sk) DEBUG_PRINT("max noise bits [" #ct "] = " << spar::utils::MaxNoise((cc), (ct), (sk)).GetMSB())

// Writes a "n,msb,noise" row to the CSV opened by RECORD_START, computing
// MaxNoise once. Gated on DEBUG_LOGGING so the decrypt compiles out otherwise.
#if defined(DEBUG_LOGGING)
#define RECORD_MAX_NOISE(n, cc, ct, sk)                              \
    do {                                                             \
        const auto rec_e_ = spar::utils::MaxNoise((cc), (ct), (sk)); \
        RECORD((n), rec_e_.GetMSB(), rec_e_);                        \
    } while (0)
#else
#define RECORD_MAX_NOISE(n, cc, ct, sk) \
    do {                                \
    } while (0);
#endif
