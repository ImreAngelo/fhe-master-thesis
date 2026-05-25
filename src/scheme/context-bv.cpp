#include "scheme/context-bv.h"

using namespace spar;


//---------------------//
// Pre-computed values //
//---------------------//

namespace {

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

/// @brief Computes B^i mod q_j used in P_q(a)
std::vector<NativeInteger> ComputePowers(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell, const uint64_t logB) {
    const auto& Q = cc.GetCryptoParameters()->GetElementParams()->GetModulus();
    const auto& q = cc.GetCryptoParameters()->GetElementParams()->GetParams();
    const auto k = q.size();

    std::vector<NativeInteger> powers(ell * k);
    
    NativeInteger B(uint64_t(1) << logB);
    NativeInteger cnt = 1;
    
    for(size_t i = 0; i < ell; i++) {
        for(size_t j = 0; j < k; j++) {
            const auto qj = q[j]->GetModulus();
            powers[i + j*ell] = cnt.Mod(qj);
        }
        
        cnt = cnt.ModMul(B, Q);
    }
    
    return powers;
}

} // namespace

BVCryptoContextImpl::BVCryptoContextImpl(const lbcrypto::CryptoContextImpl<Poly>& cc, const uint32_t ell)
    : IExtendedCryptoContextImpl(cc), m_ell(ell), m_logB(ComputeLogB(cc, m_ell)),
      m_powers(ComputePowers(cc, m_ell, m_logB))
    {}

//---------//
// Helpers //
//---------//

namespace {
    
bool IsCoefPackedPlaintext(const Plaintext& plaintext) {
    return plaintext->GetEncodingType() == lbcrypto::PlaintextEncodings::COEF_PACKED_ENCODING;
}

/// @brief Used when the cloned poly should be const except converting to a different format
Poly CloneToCoefficient(const Poly& poly) {
    auto clone = poly.Clone();
    clone.SetFormat(Format::COEFFICIENT);
    return clone;
}

} // namespace


//-----//
// API //
//-----//

RGSW BVCryptoContextImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy) const {
    const auto msg = pt->GetElement<Poly>();
    const auto zero = IsCoefPackedPlaintext(pt)
        ? this->MakeCoefPackedPlaintext({0})
        : this->MakePackedPlaintext({0});

    std::vector<Poly> digits = PowersOfBase(msg);

    const size_t k = msg.GetNumOfElements();
    const size_t half = k * m_ell;
    const size_t full = 2 * half;

    RGSW rows(full);

    // For noiseless mode, encrypt zero once so we can clone its metadata
    RLWE noiseless_template;
    if(!noisy) {
        noiseless_template = this->Encrypt(pk, zero);
    }

    #pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(full))
    for (size_t row = 0; row < full; row++) {
        size_t l = row / half;      // 0 for Upper (c_0), 1 for Lower (c_1)
        size_t rem = row % half;    // The flat index within the current half
        size_t j = rem / m_ell;     // The target tower [0 to k-1]
        size_t i = rem % m_ell;     // The base power   [0 to ell-1]

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

RLWE BVCryptoContextImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
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
    result->SetElements({ std::move(res_c0), std::move(res_c1) });
    
    return result;
}

RGSW BVCryptoContextImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const {
    RGSW result = lhs;
    for(auto& rlwe : result) rlwe = EvalExternalProduct(rlwe, rhs);
    return result;
}


//-----------//
// Internals //
//-----------//

NativeInteger BVCryptoContextImpl::GetPower(const uint32_t i, const uint32_t j) const {
    return m_powers[i + m_ell * j];
}

std::vector<Poly> BVCryptoContextImpl::PowersOfBase(const Poly& input) const {
    const auto n_towers = this->GetElementParams()->GetParams().size();

    std::vector<Poly> result(m_ell);
    result[0] = input;
    
    #pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(m_ell))
    for(size_t i = 1; i < m_ell; i++) {
        Poly scaled(input.GetParams(), input.GetFormat(), true);

        for(size_t j = 0; j < n_towers; j++) {
            auto factor = GetPower(i, j);
            auto limb = input.GetElementAtIndex(j).Times(factor);
            scaled.SetElementAtIndex(j, std::move(limb));
        }

        result[i] = std::move(scaled);
    }
    
    return result;
}

std::vector<Poly> BVCryptoContextImpl::Decompose(const Poly& input) const {
    const Poly coef = CloneToCoefficient(input);

    const size_t num_towers = coef.GetNumOfElements();
    const size_t ring_dim = coef.GetRingDimension();
    
    const uint64_t B      = 1ULL << m_logB;
    const uint64_t mask   = B - 1;
    const uint64_t offset = m_logB - 1;

    // The entire point of the optimization: we only need \ell DCRT polynomials
    std::vector<Poly> result(m_ell, Poly(coef.GetParams(), Format::COEFFICIENT, true));

    // 2. Decompose independently across towers
    #pragma omp parallel for //
    for (size_t j = 0; j < num_towers; j++) {
        
        const auto& limb = coef.GetElementAtIndex(j);
        const uint64_t q_j = limb.GetModulus().ConvertToInt();
        
        using NativePoly = std::decay_t<decltype(limb)>;
        std::vector<NativePoly> res_limbs(m_ell, NativePoly(limb.GetParams(), Format::COEFFICIENT, true));

        for (size_t x = 0; x < ring_dim; x++) {
            uint64_t a_prime = limb[x].ConvertToInt();
            
            for (size_t i = 0; i < m_ell; i++) {
                uint64_t u     = a_prime & mask;
                uint64_t carry = u >> offset;
                
                uint64_t d = u;
                if (carry) {
                    d = q_j - (B - u);
                }
                
                a_prime = (a_prime >> m_logB) + carry;
                res_limbs[i][x] = d;
            }
        }

        // Thread-safely assign the populated limbs back to the specific tower 'j' 
        // across the \ell resulting Poly objects.
        // (Since each thread owns a unique 'j', there are no write collisions on SetElementAtIndex)
        for (size_t i = 0; i < m_ell; i++) {
            result[i].SetElementAtIndex(j, std::move(res_limbs[i]));
        }
    }

    // 3. Switch back to NTT domain for fast multiplication
    for (size_t i = 0; i < m_ell; i++) {
        result[i].SetFormat(Format::EVALUATION);
    }

    return result;
}

//-------------------------//
// OpenFHE-Context Factory //
//-------------------------//

namespace {

using CCFactory = lbcrypto::CryptoContextFactory<Poly>;

struct ContextRegistrar : protected CCFactory {
    static void Register(std::shared_ptr<lbcrypto::CryptoContextImpl<Poly>> cc) {
        CCFactory::AddContext(cc);
    }
};

} // namespace

BVCryptoContext CryptoContextBV::genCryptoContext(
    const lbcrypto::CCParams<CryptoContextBV>& parameters) {
    const lbcrypto::CCParams<CryptoContextBGVRNS>& bgvParams = parameters;

    auto baseCC = lbcrypto::CryptoContextBGVRNS::genCryptoContext(bgvParams);
    auto ctx    = std::make_shared<BVCryptoContextImpl>(*baseCC, parameters.GetEll());

    ContextRegistrar::Register(ctx);
    return ctx;
}
