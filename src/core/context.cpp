#include "../utils/logging.h"
#include "../utils/timer.h"
#include "context.h"

using namespace Core;

// Constructs Z + mG using P_Q(m) as described in section 2.3.2 of the thesis 
std::vector<Ciphertext<DCRTPoly>> HPSContext::EncryptRGSW(const PublicKey<DCRTPoly>& pk, const Plaintext& plaintext, const bool noiseless) const
{
    const auto msg = plaintext->GetElement<DCRTPoly>();
    const auto zero = IsCoefPackedPlaintext(plaintext)
        ? m_params->MakeCoefPackedPlaintext({0})
        : m_params->MakePackedPlaintext({0});

    std::vector<DCRTPoly> digits = PowersOfBase(msg);

    const size_t k = msg.GetNumOfElements();
    const size_t half = k * m_ell;
    const size_t full = 2 * half;

    std::vector<Ciphertext<DCRTPoly>> rows(full);

    // For noiseless mode, encrypt zero once so we can clone its metadata
    // (key tag, encoding type, scaling factor, ...) for every row.
    Ciphertext<DCRTPoly> noiseless_template;
    if (noiseless) {
        noiseless_template = m_params->Encrypt(pk, zero);
    }

    #pragma omp parallel for // num_threads(OpenFHEParallelControls.GetThreadLimit(full))
    for (size_t row = 0; row < full; row++) {
        size_t l = row / half;      // 0 for Upper (c_0), 1 for Lower (c_1)
        size_t rem = row % half;    // The flat index within the current half
        size_t j = rem / m_ell;     // The target tower [0 to k-1]
        size_t i = rem % m_ell;     // The base power   [0 to ell-1]

        Ciphertext<DCRTPoly> ct;
        if (noiseless) {
            ct = noiseless_template->CloneEmpty();
            DCRTPoly c0(m_params->GetElementParams(), Format::EVALUATION, true);
            DCRTPoly c1(m_params->GetElementParams(), Format::EVALUATION, true);
            ct->SetElements({std::move(c0), std::move(c1)});
        } else {
            ct = m_params->Encrypt(pk, zero);
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

/// @todo implement
Ciphertext<DCRTPoly> HPSContext::EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const
{
    const size_t k = rlwe->GetElements()[0].GetNumOfElements();
    const size_t half_size = k * m_ell;

    const auto& c0 = rlwe->GetElements()[0];
    const auto& c1 = rlwe->GetElements()[1];

    // Decompose into the k*\ell broadcasted format
    std::vector<DCRTPoly> d0 = Decompose(c0);
    std::vector<DCRTPoly> d1 = Decompose(c1);

    auto params = c0.GetParams();
    DCRTPoly res_c0(params, Format::EVALUATION, true); 
    DCRTPoly res_c1(params, Format::EVALUATION, true);

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

    Ciphertext<DCRTPoly> result = rlwe->CloneEmpty(); 
    result->SetElements({ std::move(res_c0), std::move(res_c1) });
    
    return result;
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
    // DEBUG_TIMER("Powers of Base B");

    const auto n_towers = m_params->GetElementParams()->GetParams().size();

    std::vector<DCRTPoly> result(m_ell);
    result[0] = input;
    
    #pragma omp parallel for // num_threads(OpenFHEParallelControls.GetThreadLimit(m_ell))
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

std::vector<DCRTPoly> HPSContext::Decompose(const DCRTPoly &input) const
{
    const DCRTPoly coefs = CloneToCoefficient(input);
    const size_t k = coefs.GetNumOfElements();
    const size_t ring_dim = coefs.GetRingDimension();
    const uint64_t B = 1ULL << m_logB;
    const uint64_t mask = B - 1;
    const uint64_t offset = m_logB - 1;

    // The output is k * \ell fully broadcasted DCRTPolys
    std::vector<DCRTPoly> result(k * m_ell, DCRTPoly(coefs.GetParams(), Format::COEFFICIENT, true));

    #pragma omp parallel for // num_threads(OpenFHEParallelControls.GetThreadLimit(k))
    for (size_t j = 0; j < k; j++) {
        
        const auto& limb = coefs.GetElementAtIndex(j);
        using NativePoly = std::decay_t<decltype(limb)>;
        
        // Temporary storage to build the broadcasted DCRTPolys for this tower's digits
        std::vector<std::vector<NativePoly>> broadcast_limbs(m_ell);
        for (size_t i = 0; i < m_ell; i++) {
            for (size_t t = 0; t < k; t++) {
                broadcast_limbs[i].emplace_back(coefs.GetElementAtIndex(t).GetParams(), Format::COEFFICIENT, true);
            }
        }

        for (size_t x = 0; x < ring_dim; x++) {
            uint64_t a_prime = limb[x].ConvertToInt();
            
            for (size_t i = 0; i < m_ell; i++) {
                
                // THE L=1 / LOST CARRY FIX
                // If this is the final digit, absorb the remainder completely.
                if (i == m_ell - 1) {
                    for (size_t t = 0; t < k; t++) {
                        broadcast_limbs[i][t][x] = a_prime;
                    }
                    break;
                }

                uint64_t u = a_prime & mask;
                uint64_t carry = u >> offset;
                
                // Extract true signed integer
                int64_t d_signed = u;
                if (carry) d_signed -= B;
                
                a_prime = (a_prime >> m_logB) + carry;
                
                // BROADCAST to all towers 't'
                for (size_t t = 0; t < k; t++) {
                    const uint64_t qt = broadcast_limbs[i][t].GetModulus().ConvertToInt();
                    // Wrap negative numbers safely modulo qt
                    uint64_t d_mod_qt = (d_signed < 0) ? (qt - (uint64_t)(-d_signed)) : (uint64_t)d_signed;
                    broadcast_limbs[i][t][x] = d_mod_qt;
                }
            }
        }
        
        // Assemble the fully broadcasted limbs into the target DCRTPoly
        for (size_t i = 0; i < m_ell; i++) {
            DCRTPoly poly(coefs.GetParams(), Format::COEFFICIENT, true);
            for (size_t t = 0; t < k; t++) {
                poly.SetElementAtIndex(t, std::move(broadcast_limbs[i][t]));
            }
            // Switch to Evaluation domain for fast multiplication!
            poly.SetFormat(Format::EVALUATION);
            result[j * m_ell + i] = std::move(poly);
        }
    }

    return result;
}

// std::vector<DCRTPoly> HPSContext::Decompose(const DCRTPoly &input) const
// {
//     DEBUG_TIMER("Signed Digit Decomposition");
    
//     const DCRTPoly coef = CloneToCoefficient(input);

//     const size_t num_towers = coef.GetNumOfElements();
//     const size_t ring_dim = coef.GetRingDimension();
    
//     const uint64_t B      = 1ULL << m_logB;
//     const uint64_t mask   = B - 1;
//     const uint64_t offset = m_logB - 1;

//     // The entire point of the optimization: we only need \ell DCRTPolys!
//     std::vector<DCRTPoly> result(m_ell, DCRTPoly(coef.GetParams(), Format::COEFFICIENT, true));

//     // 2. Decompose independently across towers
//     #pragma omp parallel for //
//     for (size_t j = 0; j < num_towers; j++) {
        
//         const auto& limb = coef.GetElementAtIndex(j);
//         const uint64_t q_j = limb.GetModulus().ConvertToInt();
        
//         using NativePoly = std::decay_t<decltype(limb)>;
//         std::vector<NativePoly> res_limbs(m_ell, NativePoly(limb.GetParams(), Format::COEFFICIENT, true));

//         for (size_t x = 0; x < ring_dim; x++) {
//             uint64_t a_prime = limb[x].ConvertToInt();
            
//             for (size_t i = 0; i < m_ell; i++) {
//                 uint64_t u     = a_prime & mask;
//                 uint64_t carry = u >> offset;
                
//                 uint64_t d = u;
//                 if (carry) {
//                     d = q_j - (B - u);
//                 }
                
//                 a_prime = (a_prime >> m_logB) + carry;
//                 res_limbs[i][x] = d;
//             }
//         }

//         // Thread-safely assign the populated limbs back to the specific tower 'j' 
//         // across the \ell resulting DCRTPoly objects.
//         // (Since each thread owns a unique 'j', there are no write collisions on SetElementAtIndex)
//         for (size_t i = 0; i < m_ell; i++) {
//             result[i].SetElementAtIndex(j, std::move(res_limbs[i]));
//         }
//     }

//     // 3. Switch back to NTT domain for fast multiplication
//     for (size_t i = 0; i < m_ell; i++) {
//         result[i].SetFormat(Format::EVALUATION);
//     }

//     return result;
// }
