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
 * @brief Encrypt using ell and log_b
 */
std::vector<Ciphertext<DCRTPoly>> HPSContext::EncryptRGSW(const PublicKey<DCRTPoly>& pk, const Plaintext& plaintext) const
{
    const auto msg = plaintext->GetElement<DCRTPoly>();
    const auto zero = IsCoefPackedPlaintext(plaintext)
        ? m_params->MakeCoefPackedPlaintext({0})
        : m_params->MakePackedPlaintext({0});

    std::vector<DCRTPoly> digits = PowersOfBase(msg);

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(2 * digits.size());

    for(auto& digit : digits) {
        digit.SetFormat(Format::COEFFICIENT);
        DEBUG_PRINT(digit);
    }

    // // Construct the RGSW matrix rows: diagonals are Enc(digit)
    // for (size_t col = 0; col < 2; col++) {
    //     for (const auto& d : digits) {
    //         auto ct = m_params->Encrypt(pk, zero);
    //         // The digit is added to the relevant column (0 or 1) in EVALUATION format.
    //         ct->GetElements()[col] += d;
    //         rows.push_back(std::move(ct));
    //     }
    // }

    throw new std::logic_error("Not implemented");
    // return rows;
}

Ciphertext<DCRTPoly> HPSContext::EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const
{
    const auto cryptoParams = m_params->GetElementParams();
    const auto& q = cryptoParams->GetParams();
    const uint32_t k = static_cast<uint32_t>(q.size());
    const uint32_t l = m_ell;
    const uint32_t b_bits = static_cast<uint32_t>(m_logB);
    const uint32_t ringDim = cryptoParams->GetRingDimension();
    const uint64_t mask = (b_bits >= 64) ? ~uint64_t(0) : ((1ULL << b_bits) - 1);

    const auto& b = rlwe->GetElements()[0];
    const auto& a = rlwe->GetElements()[1];

    DCRTPoly result_c0(cryptoParams, Format::EVALUATION, true);
    DCRTPoly result_c1(cryptoParams, Format::EVALUATION, true);

    for (uint32_t u = 0; u < 2; u++) {
        const DCRTPoly& current_poly = (u == 0) ? b : a;

        for (uint32_t i = 0; i < k; i++) {
            NativePoly limb_coeff = current_poly.GetElementAtIndex(i);
            limb_coeff.SetFormat(Format::COEFFICIENT);

            for (uint32_t j = 0; j < l; j++) {
                const uint64_t shift = j * b_bits;
                std::vector<NativePoly> digit_limbs;
                digit_limbs.reserve(k);

                for (uint32_t mi = 0; mi < k; mi++) {
                    NativePoly digit_m(q[mi], Format::COEFFICIENT, true);

                    for (uint32_t x = 0; x < ringDim; x++) {
                        const uint64_t val = limb_coeff[x].ConvertToInt();
                        const uint64_t digit = (val >> shift) & mask;
                        digit_m[x] = digit;
                    }

                    digit_m.SetFormat(Format::EVALUATION);
                    digit_limbs.push_back(std::move(digit_m));
                }

                DCRTPoly digit_DCRT(cryptoParams, Format::EVALUATION, true);
                for (uint32_t mi = 0; mi < k; mi++) {
                    digit_DCRT.SetElementAtIndex(mi, std::move(digit_limbs[mi]));
                }

                const auto& rgsw_ct = rgsw[u * k * l + i * l + j];
                result_c0 += digit_DCRT * rgsw_ct->GetElements()[0];
                result_c1 += digit_DCRT * rgsw_ct->GetElements()[1];
            }
        }
    }

    auto result = rlwe->Clone();
    result->GetElements()[0] = std::move(result_c0);
    result->GetElements()[1] = std::move(result_c1);
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

/// @brief Returns the input polynomial scaled by B^i as (a, aB, ..., aB^{ell - 1})
std::vector<DCRTPoly> HPSContext::PowersOfBase(const DCRTPoly &input) const
{
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
