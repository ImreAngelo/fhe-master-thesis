#include "../utils/logging.h"
#include "context.h"

using namespace Core;

/**
 * @todo Convert for loop to multi-threaded in range [0..2*len)
 * @todo Multi-layer decomposition; decompose each tower into ell digits
 */
std::vector<Ciphertext<DCRTPoly>> HPSContext::Encrypt(const PublicKey<DCRTPoly> &publicKey, const Plaintext &plaintext) const
{
    const auto msg = plaintext->GetElement<DCRTPoly>();
    const auto len = m_params->GetElementParams()->GetParams().size();
    const auto zero = IsCoefPackedPlaintext(plaintext)
        ? m_params->MakeCoefPackedPlaintext({0})
        : m_params->MakePackedPlaintext({0});

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(2 * len); // * m_ell

    // Z + mG
    for(size_t col = 0; col < 2; col++) {
        for(size_t i = 0; i < len; i++) {
            auto z = m_params->Encrypt(publicKey, zero);
            z->GetElements()[col].GetAllElements()[i] += msg.GetElementAtIndex(i);
            rows.push_back(std::move(z));
        }
    }

    return rows;
}

/**
 * @todo Refactor
 */
Ciphertext<DCRTPoly> HPSContext::EvalExternalProduct(const Ciphertext<DCRTPoly> &rlwe, const std::vector<Ciphertext<DCRTPoly>> &rgsw) const
{
    const auto params = m_params->GetElementParams();
    const auto& q = params->GetParams();
    const size_t k = q.size();

    const auto& b = rlwe->GetElements()[0];
    const auto& a = rlwe->GetElements()[1];

    DCRTPoly outB(params, Format::EVALUATION, true);
    DCRTPoly outA(params, Format::EVALUATION, true);

    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(k))
    for (size_t i = 0; i < k; ++i) {
        DCRTPoly Db(params, Format::COEFFICIENT, true);
        DCRTPoly Da(params, Format::COEFFICIENT, true);

        auto bi_coef = b.GetElementAtIndex(i);  bi_coef.SetFormat(Format::COEFFICIENT);
        auto ai_coef = a.GetElementAtIndex(i);  ai_coef.SetFormat(Format::COEFFICIENT);

        for (size_t j = 0; j < k; ++j) {
            NativePoly tb(q[j], Format::COEFFICIENT, true);
            NativePoly ta(q[j], Format::COEFFICIENT, true);
            const auto qj = q[j]->GetModulus();
            for (size_t c = 0; c < bi_coef.GetLength(); ++c) {
                tb[c] = bi_coef[c].Mod(qj);
                ta[c] = ai_coef[c].Mod(qj);
            }
            Db.SetElementAtIndex(j, std::move(tb));
            Da.SetElementAtIndex(j, std::move(ta));
        }
        Db.SetFormat(Format::EVALUATION);
        Da.SetFormat(Format::EVALUATION);

        outB += rgsw[i    ]->GetElements()[0] * Db;
        outA += rgsw[i    ]->GetElements()[1] * Db;
        outB += rgsw[i + k]->GetElements()[0] * Da;
        outA += rgsw[i + k]->GetElements()[1] * Da;
    }

    auto result = rlwe->Clone();
    result->GetElements()[0] = std::move(outB);
    result->GetElements()[1] = std::move(outA);
    return result;
}

/**
 * @todo nothing. 
 */
RGSW HPSContext::EvalInternalProduct(const RGSW &lhs, const RGSW &rhs) const
{
    RGSW result = lhs;
    for(auto& rlwe : result) rlwe = EvalExternalProduct(rlwe, rhs);
    return result;
}