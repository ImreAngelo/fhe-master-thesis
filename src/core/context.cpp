#include "../utils/logging.h"
#include "../utils/timer.h"
#include "context.h"

using namespace Core;

// Constructs Z + mG using P_Q(m) as described in section 2.3.2 of the thesis 
std::vector<Ciphertext<DCRTPoly>> HPSContext::EncryptRGSW(const PublicKey<DCRTPoly>& pk, const Plaintext& plaintext) const
{
    const auto msg = plaintext->GetElement<DCRTPoly>();
    const auto zero = IsCoefPackedPlaintext(plaintext)
        ? m_params->MakeCoefPackedPlaintext({0})
        : m_params->MakePackedPlaintext({0});

    std::vector<DCRTPoly> digits = PowersOfBase(msg);

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(2 * digits.size());

    #pragma omp parallel for
    for (size_t col = 0; col < 2; col++) {
        for (const auto& d : digits) {
            auto ct = m_params->Encrypt(pk, zero);
            ct->GetElements()[col] += d;
            rows.push_back(std::move(ct));
        }
    }
    
    // for(auto& digit : digits) {
    //     digit.SetFormat(Format::COEFFICIENT);
    //     DEBUG_PRINT(digit << "\n");
    // }

    return rows;
}

/// @todo implement
Ciphertext<DCRTPoly> HPSContext::EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const
{
    throw new std::logic_error("Not implemented");
}

/// @todo nothing. 
RGSW HPSContext::EvalInternalProduct(const RGSW &lhs, const RGSW &rhs) const
{
    RGSW result = lhs;
    for(auto& rlwe : result) rlwe = EvalExternalProduct(rlwe, rhs);
    return result;
}

std::vector<DCRTPoly> HPSContext::PowersOfBase(const DCRTPoly &input) const
{
    DEBUG_TIMER("Powers of Base B");

    const auto n_towers = m_params->GetElementParams()->GetParams().size();

    std::vector<DCRTPoly> result(m_ell);
    result[0] = input;
    
    #pragma omp parallel for 
    for(size_t i = 1; i < m_ell; i++) {
        DCRTPoly scaled(input.GetParams(), input.GetFormat(), true);

        for(size_t j = 0; j < n_towers; j++) {
            auto factor = GetPower(i, j);
            auto limb = input.GetElementAtIndex(j).Times(factor);
            scaled.SetElementAtIndex(j, std::move(limb));
        }

        result[i] = std::move(scaled);
    }
    
    return result;
}
