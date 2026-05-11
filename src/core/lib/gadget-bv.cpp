#include "gadget-bv.h"

#include "utils/logging.h"
#include "utils/timer.h"

using namespace lbcrypto;

std::vector<DCRTPoly> bvrns::UnsignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly &input)
{
    // DEBUG_TIMER("NTT Digit Decomposition");

    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();
    const auto& towers = input.GetAllElements();

    // TODO: Set format
    if(input.GetFormat() != Format::EVALUATION) { DEBUG_PRINT("Plaintext was incorrect format!"); }
    
    // Output
    std::vector<DCRTPoly> g;
    g.reserve(towers.size());

    for(uint32_t i{0}; i < towers.size(); i++) {
        const auto qi{q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>()}; 
        const auto pre = (Q / BigInteger(qi)).ModInverse(qi); // TODO: Cache in context class
        
        const auto digit = input.GetElementAtIndex(i).Times(pre);

        // Project digit into all towers
        auto& row = g.emplace_back(input.GetParams(), Format::EVALUATION, true);
        auto& limbs = row.GetAllElements();
        for(uint32_t j{0}; j < towers.size(); j++) {
            const auto qj = q[j]->GetModulus();
            for(uint32_t col{0}; col < digit.GetLength(); col++) {
                limbs[j][col] = digit[col].Mod(qj);
            }
        }
    }

    return g;
}

std::vector<DCRTPoly> bvrns::SignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly &input)
{
    // DEBUG_TIMER("Coefficient Digit Decomposition");

    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();

    // Using centered [-q/2, q/2) representation cannot be done in EVALUATION format
    DCRTPoly input_coeff = input;
    input_coeff.SetFormat(Format::COEFFICIENT);

    std::vector<DCRTPoly> g(q.size(), DCRTPoly(input.GetParams(), Format::COEFFICIENT, true));

    // TODO: Use fast base extension?
    for (uint32_t i = 0; i < q.size(); i++) {
        const auto qi_int = q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>();
        const auto qi_half = qi_int >> 1; // TODO: Precalculate/cache "pre" in context
        const auto pre = (Q / BigInteger(q[i]->GetModulus())).ModInverse(q[i]->GetModulus()).ConvertToInt();
        
        const auto& limb = input_coeff.GetElementAtIndex(i);
        auto& row = g[i].GetAllElements();

        for (uint32_t k = 0; k < limb.GetLength(); k++) {
            auto t = limb[k].ModMul(pre, q[i]->GetModulus()).ConvertToInt<NativeInteger::SignedNativeInt>();
            auto d = (t < qi_half) ? t : t - qi_int;

            // Project signed value d into all towers j
            for (uint32_t j = 0; j < q.size(); j++) {
                const auto qj_int = q[j]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>();
                auto res = d % qj_int;
                if (res < 0) res += qj_int;
                
                row[j][k] = lbcrypto::NativeInteger(static_cast<uint64_t>(res));
            }
        }

        g[i].SetFormat(Format::EVALUATION);
    }

    return g;
}

std::vector<DCRTPoly> bvrns::PowerOfBase(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly &input)
{
    // DEBUG_TIMER("Projection");

    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();
    const uint32_t num_towers = q.size();

    std::vector<DCRTPoly> P;
    P.reserve(num_towers);

    for (uint32_t j = 0; j < num_towers; j++) {
        const auto& qj = q[j]->GetModulus();
        // TODO: Cache in context
        const NativeInteger pre = (Q / BigInteger(qj)).Mod(qj).ConvertToInt();
        
        DCRTPoly component(input.GetParams(), Format::EVALUATION, true);
        
        // Only limb j will be non-zero
        const auto& current_limb = input.GetElementAtIndex(j);
        auto& limbs = component.GetAllElements(); 

        for (uint32_t col = 0; col < current_limb.GetLength(); col++) {
            limbs[j][col] = current_limb[col].ModMul(pre, qj);
        }

        P.push_back(std::move(component));
    }
    
    return P;
}

std::vector<Ciphertext<DCRTPoly>> bvrns::Encrypt(const CryptoContext<DCRTPoly> &cc, const PublicKey<DCRTPoly> &publicKey, const Plaintext &plaintext)
{
    // DEBUG_TIMER("Encrypt RGSW");

    const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto& l = params->GetElementParams()->GetParams().size();
    const auto zero = (plaintext->GetEncodingType() == PlaintextEncodings::COEF_PACKED_ENCODING)
        ? cc->MakeCoefPackedPlaintext({0})
        : cc->MakePackedPlaintext({0});
        
    // TODO: Check noise Signed/Power here and performance /w pre-computed D-tables.
    const auto mg = bvrns::PowerOfBase(params, plaintext->GetElement<DCRTPoly>());

    // TODO: Check noise vs fresh zero-encryptions
    // std::vector<Ciphertext<DCRTPoly>> rows(2*l, cc->Encrypt(publicKey, zero));
    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(2*l);

    for(size_t col = 0; col < 2; col++) {
        for(const auto& mgi : mg) {
            auto z = cc->Encrypt(publicKey, zero);
            z->GetElements()[col] += mgi;
            rows.push_back(std::move(z));
        }
    }
    
    return rows;
}

Ciphertext<DCRTPoly> bvrns::EvalExternalProduct(const CryptoContext<DCRTPoly> &cc, const Ciphertext<DCRTPoly> &rlwe, const std::vector<Ciphertext<DCRTPoly>> &rgsw)
{
    // DEBUG_TIMER("External Product");

    const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

    auto c0 = rlwe->GetElements()[0];
    auto c1 = rlwe->GetElements()[1];
    c0.SetFormat(Format::EVALUATION);
    c1.SetFormat(Format::EVALUATION);

    const auto d0 = bvrns::SignedDigitDecompose(params, c0);
    const auto d1 = bvrns::SignedDigitDecompose(params, c1);
    const size_t K = d0.size();  // L * ell

    // Build outputs at the RLWE's active level, not the full context chain.
    const auto& activeParams = c0.GetParams();
    DCRTPoly out0(activeParams, Format::EVALUATION, true);
    DCRTPoly out1(activeParams, Format::EVALUATION, true);
    for (size_t i = 0; i < K; i++) {
        const auto& m0 = rgsw[i]->GetElements();
        const auto& m1 = rgsw[K + i]->GetElements();
        out0 += d0[i] * m0[0];
        out1 += d0[i] * m0[1];
        out0 += d1[i] * m1[0];
        out1 += d1[i] * m1[1];
    }

    auto result = rlwe->Clone();
    result->GetElements()[0] = std::move(out0);
    result->GetElements()[1] = std::move(out1);

    return result;
}

std::vector<Ciphertext<DCRTPoly>> bvrns::EvalInternalProduct(const CryptoContext<DCRTPoly> &cc, const std::vector<Ciphertext<DCRTPoly>> &lhs, const std::vector<Ciphertext<DCRTPoly>> &rhs)
{
    // DEBUG_TIMER("Internal Product");

    std::vector<Ciphertext<DCRTPoly>> result = lhs;
    for(auto& rlwe : result) rlwe = EvalExternalProduct(cc, rlwe, rhs);
    return result;
}

DecryptResult bvrns::Decrypt(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly> &privateKey, const std::vector<Ciphertext<DCRTPoly>> &ciphertext, Plaintext *plaintext)
{
    const auto idx = ciphertext.size()/2 - 1;
    return cc->Decrypt(privateKey, ciphertext[idx], plaintext);
}

/**
 * POTENTIAL OPTIMIZATIONS
 *  - Move to context class and pre-compute tables
 *  - Optimize external product DCRT access
 *      - Directly access the limbs instead of using the += operator
 *  - OpenMP multithreading
 *  - Hybrid NTT/Coefficient decomposition 
 *      - (UnsignedDigitDecompose can stay in eval mode for most of the operations, just not centering)
 *  - Investigate noise of using the same zero-ciphertexts vs fresh encryptions each iteration
 *      - Or pre-calc and cache (and reuse) the zero-encryptions
 *  - Use HPS optimization/fast base extension in decomposition 
 *  - 128-bit lazy reduction
 *  - Enable AVX512 instruction set
 */