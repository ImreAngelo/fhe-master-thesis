#include "context-bv.h"
#include "core/utils/logging.h"
#include "factory.h"

namespace {
using namespace core;

//---------------------//
// Pre-computed values //
//---------------------//

/// @brief Computes B from ell so that ell digits in base B covers max(q_i) with one bit of headroom for the decomposition offset
uint64_t ComputeLogB(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell) {
    const auto& params = cc.GetCryptoParameters()->GetElementParams()->GetParams();
    uint32_t max_msb = 0;
    for (const auto& qi : params) {
        uint32_t msb = qi->GetModulus().GetMSB();
        if (msb > max_msb) max_msb = msb;
    }
    return (max_msb + ell) / ell;
}

/// @brief Computes the decomposition offset for parallel signed digit decomposition
uint64_t ComputeOffset(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell, const uint64_t logB) {
    const uint64_t halfB = uint64_t(1) << (logB - 1);
    uint64_t offset = 0;
    for (uint32_t i = 0; i + 1 < ell; i++)  // the last digit is already [0, B/2)
        offset += halfB << (i * logB);
    return offset;  // (B/2)(B^(ell-1) - 1)/(B - 1)
}

/// @brief Computes B^i mod q_j used in the per-limb digit decomposition in P_q(a) for i up to ell
std::vector<NativeInteger> ComputePowers(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell, const uint64_t logB) {
    const auto& Q = cc.GetCryptoParameters()->GetElementParams()->GetModulus();
    const auto& q = cc.GetCryptoParameters()->GetElementParams()->GetParams();
    const auto k = q.size();

    std::vector<NativeInteger> powers(ell * k);

    NativeInteger B(uint64_t(1) << logB);
    NativeInteger cnt = 1;  // current B^i

    for (size_t i = 0; i < ell; i++) {
        for (size_t j = 0; j < k; j++) {
            const auto qj = q[j]->GetModulus();
            powers[i + j * ell] = cnt.Mod(qj);
        }

        cnt = cnt.ModMul(B, Q);
    }

    return powers;
}

//---------//
// Helpers //
//---------//

bool IsCoefPackedPlaintext(const Plaintext& plaintext) {
    return plaintext->GetEncodingType() == lbcrypto::PlaintextEncodings::COEF_PACKED_ENCODING;
}

/// @brief Used when the cloned poly should be const except converting to a different format
// Poly CloneToCoefficient(const Poly& poly) {
//     auto clone = poly.Clone();
//     clone.SetFormat(Format::COEFFICIENT);
//     return clone;
// }

}  // namespace


namespace core {

ExtendedContextBVImpl::ExtendedContextBVImpl(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell)
    : IExtendedContext(cc),
      m_ell(ell),
      m_logB(ComputeLogB(cc, m_ell)),
      m_offset(ComputeOffset(cc, m_ell, m_logB)),
      m_powers(ComputePowers(cc, m_ell, m_logB)) {}


//-----//
// API //
//-----//

RGSW ExtendedContextBVImpl::MakePublicRGSW(const PublicKey& pk, const Plaintext& pt) const {
    // clang-format off
    const auto msg = pt->GetElement<Poly>();
    const auto zero = IsCoefPackedPlaintext(pt)
        ? this->MakeCoefPackedPlaintext({0})
        : this->MakePackedPlaintext({0});
    // clang-format on

    const size_t k = msg.GetNumOfElements();
    const size_t l = k * m_ell;

    // Noiseless zero row: only the metadata of the encryption is kept
    RLWE z = this->Encrypt(pk, zero);
    z->SetElements({
        Poly(this->GetElementParams(), Format::EVALUATION, true),
        Poly(this->GetElementParams(), Format::EVALUATION, true),
    });

    RGSW rows(2 * l);

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(l))
    for (size_t r = 0; r < l; r++) {
        const size_t i = r % m_ell;  // The base power   [0, ell)
        const size_t j = r / m_ell;  // The target tower [0, k)

        const auto scaled = msg.GetElementAtIndex(j).Times(GetPower(i, j));

        auto ct0 = z->Clone();
        auto ct1 = z->Clone();
        ct0->GetElements()[0].GetAllElements()[j] += scaled;
        ct1->GetElements()[1].GetAllElements()[j] += scaled;

        rows[r] = std::move(ct0);
        rows[r + l] = std::move(ct1);
    }

    return rows;
}

RGSW ExtendedContextBVImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt) const {
    // clang-format off
    const auto msg = pt->GetElement<Poly>();
    const auto zero = IsCoefPackedPlaintext(pt)
        ? this->MakeCoefPackedPlaintext({0})
        : this->MakePackedPlaintext({0});
    // clang-format on

    const size_t k = msg.GetNumOfElements();
    const size_t l = k * m_ell;

    RGSW rows(2 * l);

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(l))
    for (size_t r = 0; r < l; r++) {
        const size_t i = r % m_ell;  // The base power   [0, ell)
        const size_t j = r / m_ell;  // The target tower [0, k)

        const auto scaled = msg.GetElementAtIndex(j).Times(GetPower(i, j));

        auto ct0 = this->Encrypt(pk, zero);
        auto ct1 = this->Encrypt(pk, zero);
        ct0->GetElements()[0].GetAllElements()[j] += scaled;
        ct1->GetElements()[1].GetAllElements()[j] += scaled;

        rows[r] = std::move(ct0);
        rows[r + l] = std::move(ct1);
    }

    return rows;
}

// TODO: Multi-thread this function
// RLWE ExtendedContextBVImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
//     const size_t k = rlwe->GetElements()[0].GetNumOfElements();
//     const size_t l = k * m_ell;

//     const auto& c0 = rlwe->GetElements()[0];
//     const auto& c1 = rlwe->GetElements()[1];

//     // Decompose into the k*\ell broadcasted format
//     std::vector<Poly> d0 = Decompose(c0);
//     std::vector<Poly> d1 = Decompose(c1);

//     auto params = c0.GetParams();
//     Poly acc0(params, Format::EVALUATION, true);
//     Poly acc1(params, Format::EVALUATION, true);

//     // Inner product
//     for (size_t r = 0; r < l; r++) {
//         const auto& rUpper = rgsw[r]->GetElements();
//         const auto& rLower = rgsw[l + r]->GetElements();
//         acc0 += d0[r] * rUpper[0] + d1[r] * rLower[0];
//         acc1 += d0[r] * rUpper[1] + d1[r] * rLower[1];
//     }

//     RLWE result = rlwe->CloneEmpty();
//     result->SetElements({std::move(acc0), std::move(acc1)});

//     return result;
// }

RLWE ExtendedContextBVImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
    const auto& cv = rlwe->GetElements();  // (c0, c1), EVALUATION format
    const auto params = cv[0].GetParams();
    const size_t k = cv[0].GetNumOfElements();
    const size_t n = params->GetRingDimension();
    const size_t l = k * m_ell;  // digits per component
    const size_t S = 2 * l;      // digit slot s = c*l + r matches rgsw row s

    const uint64_t mask = (uint64_t(1) << m_logB) - 1;
    const uint64_t halfB = uint64_t(1) << (m_logB - 1);

    // ---------- Stage 1: iNTT, 2k independent tower tasks ----------
    // coef[c*k + jt] = tower jt of component c, in COEFFICIENT format
    std::vector<NativePoly> coef(2 * k);

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(2 * k))
    for (size_t u = 0; u < 2 * k; u++) {
        coef[u] = cv[u / k].GetElementAtIndex(u % k);  // per-tower copy
        coef[u].SetFormat(Format::COEFFICIENT);        // single-tower iNTT
    }

    // ---------- Stage 2: slice + lift + fNTT, 2*k*ell*k independent tasks ----------
    // dig[s*k + t] = tower t of digit slot s, in EVALUATION format
    std::vector<NativePoly> dig(S * k);

#pragma omp parallel for collapse(2) num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(S* k))
    for (size_t s = 0; s < S; s++) {
        for (size_t t = 0; t < k; t++) {
            const size_t r = s % l;
            const size_t iT = r / m_ell;  // source tower -- matches EncryptRGSW
            const size_t j = r % m_ell;   // base power
            const size_t sh = j * m_logB;
            const bool top = (j + 1 == m_ell);  // top digit: unsigned, no B/2 shift

            const auto& limb = coef[(s / l) * k + iT];
            const auto& tp = params->GetParams()[t];
            const uint64_t qt = tp->GetModulus().ConvertToInt();

            NativePoly dt(tp, Format::COEFFICIENT, true);
            for (size_t x = 0; x < n; x++) {
                const uint64_t u = ((limb[x].ConvertToInt() + m_offset) >> sh) & mask;
                dt[x] = top ? NativeInteger(u) : NativeInteger(u >= halfB ? u - halfB : qt - (halfB - u));
            }

            dt.SetFormat(Format::EVALUATION);  // single-tower fNTT
            dig[s * k + t] = std::move(dt);
        }
    }

    // ---------- Stage 3: accumulation, separable over (b, t): no reduction ----------
    Poly acc0(params, Format::EVALUATION, true);
    Poly acc1(params, Format::EVALUATION, true);
    Poly* acc[2] = {&acc0, &acc1};

#pragma omp parallel for collapse(2) num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(2 * k))
    for (size_t b = 0; b < 2; b++) {
        for (size_t t = 0; t < k; t++) {
            const auto& tp = params->GetParams()[t];
            NativePoly sum(tp, Format::EVALUATION, true);

            for (size_t s = 0; s < S; s++)  // sequential FMA, contention-free
                sum += dig[s * k + t] * rgsw[s]->GetElements()[b].GetElementAtIndex(t);

            acc[b]->SetElementAtIndex(t, std::move(sum));
        }
    }

    RLWE result = rlwe->CloneEmpty();
    result->SetElements({std::move(acc0), std::move(acc1)});
    return result;
}

RGSW ExtendedContextBVImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const {
    RGSW result = lhs;
    for (auto& rlwe : result) rlwe = EvalExternalProduct(rlwe, rhs);
    return result;
}

RGSW ExtendedContextBVImpl::EvalAddRGSW(const RGSW& lhs, const RGSW& rhs) const {
    if (lhs.size() != rhs.size()) {
        OPENFHE_THROW("EvalAddRGSW expects RGSW ciphertexts with the same number of rows");
    }

    RGSW result(lhs.size());

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(lhs.size()))
    for (size_t r = 0; r < lhs.size(); r++) {
        auto out = lhs[r]->Clone();

        const auto& cL = lhs[r]->GetElements();
        const auto& cR = rhs[r]->GetElements();

        out->SetElements({cL[0] + cR[0], cL[1] + cR[1]});
        result[r] = std::move(out);
    }

    return result;
}

RGSW ExtendedContextBVImpl::EvalSubRGSW(const RGSW& lhs, const RGSW& rhs) const {
    if (lhs.size() != rhs.size()) {
        OPENFHE_THROW("EvalSubRGSW expects RGSW ciphertexts with the same number of rows");
    }

    RGSW result(lhs.size());

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(lhs.size()))
    for (size_t r = 0; r < lhs.size(); r++) {
        auto out = lhs[r]->Clone();

        const auto& cL = lhs[r]->GetElements();
        const auto& cR = rhs[r]->GetElements();

        out->SetElements({cL[0] - cR[0], cL[1] - cR[1]});
        result[r] = std::move(out);
    }

    return result;
}

RGSW ExtendedContextBVImpl::EvalMultRGSW(const RGSW& rgsw, const Plaintext& pt) const {
    Poly p = pt->GetElement<Poly>();
    p.SetFormat(Format::EVALUATION);

    RGSW result(rgsw.size()); // 2 * m_ell

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(rgsw.size()))
    for (size_t r = 0; r < rgsw.size(); r++) {
        auto out = rgsw[r]->Clone();

        const auto& c = rgsw[r]->GetElements();

        out->SetElements({c[0] * p, c[1] * p});
        result[r] = std::move(out);
    }

    return result;
}

//-----------//
// Internals //
//-----------//

NativeInteger ExtendedContextBVImpl::GetPower(const uint32_t i, const uint32_t j) const {
    return m_powers[i + m_ell * j];
}

// std::vector<Poly> ExtendedContextBVImpl::Decompose(const Poly& x) const {
//     const auto params = x.GetParams();
//     const size_t k = x.GetNumOfElements();
//     const size_t n = params->GetRingDimension();
//     const size_t l = k * m_ell;

//     const uint64_t mask = (uint64_t(1) << m_logB) - 1;
//     const uint64_t halfB = uint64_t(1) << (m_logB - 1);

//     Poly xCoef = x;
//     xCoef.SetFormat(Format::COEFFICIENT);

//     std::vector<Poly> digits(l);

// #pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(l))
//     for (size_t r = 0; r < l; r++) {
//         const size_t i = r / m_ell;
//         const size_t j = r % m_ell;
//         const size_t sh = j * m_logB;

//         const auto& limb = xCoef.GetElementAtIndex(i);

//         // Center digit
//         std::vector<uint64_t> u(n);
//         for (size_t c = 0; c < n; c++) u[c] = ((limb[c].ConvertToInt() + m_offset) >> sh) & mask;

//         Poly d(params, Format::COEFFICIENT, true);
//         for (size_t t = 0; t < k; t++) {
//             const auto& tp = params->GetParams()[t];
//             const uint64_t qt = tp->GetModulus().ConvertToInt();
//             NativePoly dt(tp, Format::COEFFICIENT, true);
//             for (size_t c = 0; c < n; c++)
//                 dt[c] = (j + 1 < m_ell) ? NativeInteger(u[c] >= halfB ? u[c] - halfB : qt - (halfB - u[c])) : NativeInteger(u[c]);
//             d.SetElementAtIndex(t, std::move(dt));
//         }
//         d.SetFormat(Format::EVALUATION);
//         digits[r] = std::move(d);
//     }
//     return digits;
// }

// std::vector<Poly> ExtendedContextBVImpl::Decompose(const Poly& input) const {
//     const Poly coefs = ::CloneToCoefficient(input);
//     const size_t k = coefs.GetNumOfElements();
//     const size_t ring_dim = coefs.GetRingDimension();
//     const uint64_t B = 1ULL << m_logB;
//     const uint64_t mask = B - 1;
//     const uint64_t offset = m_logB - 1;

//     // The output is k * \ell fully broadcasted Polys
//     using NativePoly = std::decay_t<decltype(coefs.GetElementAtIndex(0))>;
//     std::vector<Poly> result(k * m_ell, Poly(coefs.GetParams(), Format::COEFFICIENT, true));

//     // Per-tower moduli are identical for every output Poly (all share coefs' params)
//     std::vector<uint64_t> moduli(k);
//     for (size_t t = 0; t < k; t++) {
//         moduli[t] = coefs.GetElementAtIndex(t).GetModulus().ConvertToInt();
//     }

// #pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(k))
//     for (size_t j = 0; j < k; j++) {
//         const auto& limb = coefs.GetElementAtIndex(j);

//         // Mutable views into the pre-allocated target limbs for this tower's digits
//         std::vector<std::vector<NativePoly>*> out(m_ell);
//         for (size_t i = 0; i < m_ell; i++) {
//             out[i] = &result[j * m_ell + i].GetAllElements();
//         }

//         for (size_t x = 0; x < ring_dim; x++) {
//             uint64_t a_prime = limb[x].ConvertToInt();

//             for (size_t i = 0; i < m_ell; i++) {
//                 // If this is the final digit, absorb the remainder completely
//                 if (i == m_ell - 1) {
//                     for (size_t t = 0; t < k; t++) {
//                         (*out[i])[t][x] = a_prime;
//                     }
//                     break;
//                 }

//                 uint64_t u = a_prime & mask;
//                 uint64_t carry = u >> offset;

//                 // Extract true signed integer
//                 int64_t d_signed = u;
//                 if (carry) d_signed -= B;

//                 a_prime = (a_prime >> m_logB) + carry;

//                 // Broadcast to all towers
//                 for (size_t t = 0; t < k; t++) {
//                     const uint64_t qt = moduli[t];
//                     uint64_t d_mod_qt = (d_signed < 0) ? (qt - (uint64_t)(-d_signed)) : (uint64_t)d_signed;
//                     (*out[i])[t][x] = d_mod_qt;
//                 }
//             }
//         }

//         // Limbs were written in COEFFICIENT format; convert each result Poly in place
//         for (size_t i = 0; i < m_ell; i++) {
//             result[j * m_ell + i].SetFormat(Format::EVALUATION);
//         }
//     }

//     return result;
// }


//-------------------------//
// OpenFHE-Context Factory //
//-------------------------//

ExtendedContext GenContextBV(const lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>& parameters, const uint32_t ell) {
    auto baseCC = lbcrypto::GenCryptoContext(parameters);
    auto ext = std::make_shared<ExtendedContextBVImpl>(*baseCC, ell);
    factory::FactoryRegistrar<Poly>::Add(ext);
    return ext;
}

}  // namespace core