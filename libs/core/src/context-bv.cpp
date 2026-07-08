#include "context-bv.h"
#include "factory.h"


namespace {
using namespace core;

//---------------------//
// Pre-computed values //
//---------------------//

/// @brief Computes B from ell so that ell digits in base B covers max(q_i)
uint64_t ComputeLogB(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell) {
    const auto& params = cc.GetCryptoParameters()->GetElementParams()->GetParams();
    uint32_t max_msb = 0;
    for (const auto& qi : params) {
        uint32_t msb = qi->GetModulus().GetMSB();
        if (msb > max_msb) max_msb = msb;
    }
    return (max_msb + ell - 1) / ell;
}

/// @brief Computes B^i mod q_j used in the per-limb digit decomposition in P_q(a) for i up to ell
std::vector<NativeInteger> ComputePowers(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell, const uint64_t logB) {
    const auto& Q = cc.GetCryptoParameters()->GetElementParams()->GetModulus();
    const auto& q = cc.GetCryptoParameters()->GetElementParams()->GetParams();
    const auto k = q.size();

    std::vector<NativeInteger> powers(ell * k);

    NativeInteger B(uint64_t(1) << logB);
    NativeInteger cnt = 1; // current B^i

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
Poly CloneToCoefficient(const Poly& poly) {
    auto clone = poly.Clone();
    clone.SetFormat(Format::COEFFICIENT);
    return clone;
}

}  // namespace


namespace core {

ExtendedContextBVImpl::ExtendedContextBVImpl(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell)
    : IExtendedContext(cc), m_ell(ell), m_logB(ComputeLogB(cc, m_ell)), m_powers(ComputePowers(cc, m_ell, m_logB)) {}


//-----//
// API //
//-----//

RGSW ExtendedContextBVImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy) const {
    // clang-format off
    const auto msg = pt->GetElement<Poly>();
    const auto zero = IsCoefPackedPlaintext(pt)
        ? this->MakeCoefPackedPlaintext({0})
        : this->MakePackedPlaintext({0});
    // clang-format on

    std::vector<Poly> digits = PowersOfBase(msg);

    const size_t k = msg.GetNumOfElements();
    const size_t half = k * m_ell;
    const size_t full = 2 * half;

    RGSW rows(full);

    // For noiseless mode, encrypt zero once so we can clone its metadata
    RLWE noiseless_template;
    if (!noisy) {
        noiseless_template = this->Encrypt(pk, zero);
    }

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(full))
    for (size_t row = 0; row < full; row++) {
        size_t l = row / half;    // 0 for Upper (c_0), 1 for Lower (c_1)
        size_t rem = row % half;  // The flat index within the current half
        size_t j = rem / m_ell;   // The target tower [0 to k-1]
        size_t i = rem % m_ell;   // The base power   [0 to ell-1]

        RLWE ct;
        if (!noisy) {
            ct = noiseless_template->CloneEmpty();
            Poly c0(this->GetElementParams(), Format::EVALUATION, true);
            Poly c1(this->GetElementParams(), Format::EVALUATION, true);
            ct->SetElements({std::move(c0), std::move(c1)});
        } else {
            ct = this->Encrypt(pk, zero);
        }
        auto elements = ct->GetElements();

        auto target_limb = elements[l].GetElementAtIndex(j);
        target_limb += digits[i].GetElementAtIndex(j);
        elements[l].SetElementAtIndex(j, std::move(target_limb));
        ct->SetElements(std::move(elements));
        rows[row] = std::move(ct);
    }

    return rows;
}

RLWE ExtendedContextBVImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
    const size_t k = rlwe->GetElements()[0].GetNumOfElements();
    const size_t half_size = k * m_ell;

    const auto& c0 = rlwe->GetElements()[0];
    const auto& c1 = rlwe->GetElements()[1];

    // Decompose into the k*\ell broadcasted format
    std::vector<Poly> d0 = Decompose(c0);
    std::vector<Poly> d1 = Decompose(c1);

    auto params = c0.GetParams();
    Poly res_c0(params, Format::EVALUATION, true);
    Poly res_c1(params, Format::EVALUATION, true);

    // Multiply the k*ell decomposed polynomials against the k*ell RGSW rows
    for (size_t idx = 0; idx < half_size; idx++) {
        // --- Upper Half (C_0 interacts strictly with d0) ---
        const auto& C0_row = rgsw[idx]->GetElements();
        res_c0 += d0[idx] * C0_row[0];
        res_c1 += d0[idx] * C0_row[1];

        // --- Lower Half (C_1 interacts strictly with d1) ---
        const auto& C1_row = rgsw[half_size + idx]->GetElements();
        res_c0 += d1[idx] * C1_row[0];
        res_c1 += d1[idx] * C1_row[1];
    }

    RLWE result = rlwe->CloneEmpty();
    result->SetElements({std::move(res_c0), std::move(res_c1)});

    return result;
}

RGSW ExtendedContextBVImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const {
    RGSW result = lhs;
    for (auto& rlwe : result) rlwe = EvalExternalProduct(rlwe, rhs);
    return result;
}


//-----------//
// Internals //
//-----------//

NativeInteger ExtendedContextBVImpl::GetPower(const uint32_t i, const uint32_t j) const {
    return m_powers[i + m_ell * j];
}

std::vector<Poly> ExtendedContextBVImpl::PowersOfBase(const Poly& input) const {
    const auto n_towers = this->GetElementParams()->GetParams().size();

    std::vector<Poly> result(m_ell);
    result[0] = input;

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(m_ell))
    for (size_t i = 1; i < m_ell; i++) {
        Poly scaled(input.GetParams(), input.GetFormat(), true);

        // TODO: Test flattened for loop to see if it is faster than the nested loop
        for (size_t j = 0; j < n_towers; j++) {
            auto factor = GetPower(i, j);
            auto limb = input.GetElementAtIndex(j).Times(factor);
            scaled.SetElementAtIndex(j, std::move(limb));
        }

        result[i] = std::move(scaled);
    }

    return result;
}

std::vector<Poly> ExtendedContextBVImpl::Decompose(const Poly& input) const {
    const Poly coefs = ::CloneToCoefficient(input);
    const size_t k = coefs.GetNumOfElements();
    const size_t ring_dim = coefs.GetRingDimension();
    const uint64_t B = 1ULL << m_logB;
    const uint64_t mask = B - 1;
    const uint64_t offset = m_logB - 1;

    // The output is k * \ell fully broadcasted Polys
    using NativePoly = std::decay_t<decltype(coefs.GetElementAtIndex(0))>;
    std::vector<Poly> result(k * m_ell, Poly(coefs.GetParams(), Format::COEFFICIENT, true));

    // Per-tower moduli are identical for every output Poly (all share coefs' params)
    std::vector<uint64_t> moduli(k);
    for (size_t t = 0; t < k; t++) {
        moduli[t] = coefs.GetElementAtIndex(t).GetModulus().ConvertToInt();
    }

#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(k))
    for (size_t j = 0; j < k; j++) {
        const auto& limb = coefs.GetElementAtIndex(j);

        // Mutable views into the pre-allocated target limbs for this tower's digits
        std::vector<std::vector<NativePoly>*> out(m_ell);
        for (size_t i = 0; i < m_ell; i++) {
            out[i] = &result[j * m_ell + i].GetAllElements();
        }

        for (size_t x = 0; x < ring_dim; x++) {
            uint64_t a_prime = limb[x].ConvertToInt();

            for (size_t i = 0; i < m_ell; i++) {
                // If this is the final digit, absorb the remainder completely
                if (i == m_ell - 1) {
                    for (size_t t = 0; t < k; t++) {
                        (*out[i])[t][x] = a_prime;
                    }
                    break;
                }

                uint64_t u = a_prime & mask;
                uint64_t carry = u >> offset;

                // Extract true signed integer
                int64_t d_signed = u;
                if (carry) d_signed -= B;

                a_prime = (a_prime >> m_logB) + carry;

                // Broadcast to all towers
                for (size_t t = 0; t < k; t++) {
                    const uint64_t qt = moduli[t];
                    uint64_t d_mod_qt = (d_signed < 0) ? (qt - (uint64_t)(-d_signed)) : (uint64_t)d_signed;
                    (*out[i])[t][x] = d_mod_qt;
                }
            }
        }

        // Limbs were written in COEFFICIENT format; convert each result Poly in place
        for (size_t i = 0; i < m_ell; i++) {
            result[j * m_ell + i].SetFormat(Format::EVALUATION);
        }
    }

    return result;
}


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