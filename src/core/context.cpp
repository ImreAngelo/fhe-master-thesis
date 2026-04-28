#include "context.h"
#include "utils/timer.h"


namespace Context
{
    template <typename T>
    ExtendedCryptoContextImpl<T>::ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params)
        : CryptoContextImpl<T>(base), m_params(params) {}

    template <typename T>
    Ciphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalExternalProduct(
        const Ciphertext<DCRTPoly>& x,
        const RGSWCiphertext<DCRTPoly>& Y
    ) {
        DEBUG_TIMER("External Product");

        // TODO: Document GadgetBase is not gadget base, but rather 2^base
        const uint64_t log_B = m_params.GetGadgetBase();

        // RNS-friendly gadget decomposition: per (tower, base-B digit). CRTDecompose
        // returns digits already in DCRT form (no big-integer interpolation), and the
        // total digit count = sum_i ceil(log2(q_i) / log_B). Noise scales with the
        // per-digit value (~B), not with the full Q, so increasing ell genuinely
        // reduces external-product noise.
        const DCRTPoly& b = x->GetElements()[0];
        const DCRTPoly& a = x->GetElements()[1];

        std::vector<DCRTPoly> v = b.CRTDecompose(log_B);
        std::vector<DCRTPoly> u = a.CRTDecompose(log_B);

        // Y was built at full Q with layout
        //   G[0      .. nFull)        top rows    (encrypt m * gadget_{i,d} * s)
        //   G[nFull  .. 2*nFull)      bottom rows (encrypt m * gadget_{i,d})
        // indexed by (tower i, digit d) in row-major order. After x is rescaled,
        // BGV ModReduce drops the trailing towers, so CRTDecompose returns digits
        // for towers 0..m-1 only — i.e., a prefix of the gadget. The per-tower
        // alignment in ScalarMultCiphertext drops the matching trailing towers
        // of each cloned Y[j] before multiplying.
        const size_t nFull = Y.size() / 2;

        if (u.size() != v.size())
            throw std::runtime_error("EvalExternalProduct: a/b decomposition size mismatch");
        if (u.size() > nFull)
            throw std::runtime_error("EvalExternalProduct: x has more digits than gadget supports");

        auto result = ScalarMultCiphertext(Y[0], u[0]);
        for (size_t j = 1; j < u.size(); j++)
            result = this->EvalAdd(result, ScalarMultCiphertext(Y[j],         u[j]));
        for (size_t j = 0; j < v.size(); j++)
            result = this->EvalAdd(result, ScalarMultCiphertext(Y[j + nFull], v[j]));

        return result;
    }

    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalInternalProduct(
        const RGSWCiphertext<DCRTPoly> &left, 
        const RGSWCiphertext<DCRTPoly> &right
    ) {
        DEBUG_TIMER("Internal Product");
        
        RGSWCiphertext<DCRTPoly> result(left.size());
        for(size_t i = 0; i < left.size(); i++)
            result[i] = this->EvalExternalProduct(left[i], right);
        return result;
    }

    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EncryptRGSW(
        const PublicKey<DCRTPoly>& publicKey,
        std::vector<int64_t> msg    // TODO: Pass plaintext (optionally std::move)
    ) {
        DEBUG_TIMER("Encrypt RGSW");

        // TODO: Document GadgetBase is not gadget base, but rather 2^base
        const uint64_t log_B = m_params.GetGadgetBase();
        const NativeInteger B(1ULL << log_B);

        const Plaintext zero   = this->MakePackedPlaintext({ 0 });
        const Plaintext mPlain = this->MakePackedPlaintext(msg);

        if (!mPlain->Encode())
            throw std::runtime_error("Failed to encode plaintext");

        DCRTPoly mDCRT = mPlain->GetElement<DCRTPoly>();
        mDCRT.SetFormat(Format::EVALUATION);

        // RNS gadget: one entry per (tower i, base-B digit d). The gadget element
        // g_{i,d} has value B^d in tower i and 0 in every other tower (i.e., the
        // CRT idempotent for tower i scaled by B^d). Pairing this gadget with
        // CRTDecompose gives a a = sum_{i,d} dec_{i,d}(a) * g_{i,d} (mod Q),
        // matching what CRTDecompose returns.
        const auto& mTowers    = mDCRT.GetAllElements();
        const size_t numTowers = mTowers.size();

        std::vector<size_t> digitsPerTower(numTowers);
        size_t nWindows = 0;
        for (size_t i = 0; i < numTowers; i++) {
            const uint32_t nBits = mTowers[i].GetModulus().GetLengthForBase(2);
            const size_t d       = (nBits + log_B - 1) / log_B;
            digitsPerTower[i]    = d;
            nWindows            += d;
        }

        RGSWCiphertext<DCRTPoly> G(2 * nWindows);

        size_t j = 0;
        for (size_t i = 0; i < numTowers; i++) {
            const NativeInteger& q_i = mTowers[i].GetModulus();
            NativeInteger Bd(1);

            for (size_t d = 0; d < digitsPerTower[i]; d++) {
                // Build m * g_{i,d}: tower i = (m * B^d) mod q_i, zero elsewhere.
                DCRTPoly gm(mDCRT.GetParams(), Format::EVALUATION, true);
                gm.GetAllElements()[i] = mTowers[i] * Bd;

                // Bottom row (j + nWindows): encrypts m * g_{i,d}; inject into c0.
                {
                    auto bot     = this->Encrypt(publicKey, zero);
                    auto& elems  = bot->GetElements();
                    DCRTPoly add = gm;
                    add.SetFormat(elems[0].GetFormat());
                    elems[0] += add;
                    G[j + nWindows] = bot;
                }

                // Top row (j): encrypts m * g_{i,d} * s; inject into c1.
                {
                    auto top     = this->Encrypt(publicKey, zero);
                    auto& elems  = top->GetElements();
                    DCRTPoly add = gm;
                    add.SetFormat(elems[1].GetFormat());
                    elems[1] += add;
                    G[j] = top;
                }

                Bd = Bd.ModMul(B, q_i);
                j++;
            }
        }

        return G;
    }

    template <typename T>
    RGSWCiphertext<T> ExtendedCryptoContextImpl<T>::ExpandRLWEHoisted(
        const Ciphertext<T>& ciphertext,
        const PublicKey<T>& publicKey,
        const uint32_t len
    ) {
        // const auto len = (uint32_t(1) << m_params.GetGadgetLevels()); // Only works if number of bits is power of 2
        const auto ciphertext_n = this->Encrypt(publicKey, this->MakePackedPlaintext({ 1 }));

        RGSWCiphertext<T> c(len);
        c[0] = this->EvalMult(ciphertext, ciphertext_n);

        // TODO: Confirm that EvalFastRotation doesn't use secret keys/that all necessary key material is included in serialization
        const auto precomputed = this->EvalFastRotationPrecompute(ciphertext);
        for(uint32_t i = 1; i < len; i++) {
            const auto rotated = this->EvalFastRotation(ciphertext, i, precomputed);
            c[i] = this->EvalMult(rotated, ciphertext_n);
        }

        return c;
    }

    template <typename T>
    Ciphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::ScalarMultCiphertext(
        const Ciphertext<DCRTPoly>& ct,
        const DCRTPoly& scalar
    ) {
        auto result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ct);
        auto& elems = result->GetElements();

        // Align towers: drop the last towers of the cloned ciphertext to match
        // the scalar's CRT tower count. This is needed when ct is a fresh RGSW
        // element (full Q) and scalar comes from a rescaled RLWE ciphertext.
        const size_t target = scalar.GetNumOfElements();
        const size_t cur    = elems[0].GetNumOfElements();
        if (cur > target) {
            const size_t drop = cur - target;
            for (auto& e : elems)
                e.DropLastElements(drop);
            result->SetLevel(result->GetLevel() + drop);
        }

        elems[0] *= scalar;
        elems[1] *= scalar;
        return result;
    }

    template class ExtendedCryptoContextImpl<DCRTPoly>;
}


// inline RingGSWCiphertext<T> ScaleToGadgetLevels(Ciphertext<T>& ct) {
//     const uint32_t ell = m_params.GetGadgetLevels();
//     const usint B      = m_params.GetGadgetBase();
//     std::vector<Ciphertext<T>> result(ell);
//     // TODO: Assert overflow conditions
//     auto t_int = this->GetCryptoParameters()->GetPlaintextModulus();
//     auto bound = static_cast<int64_t>(t_int >> 1);
//     NativeInteger t(t_int);
//     NativeInteger b(B);
//     #if defined(ASSERTIONS) && ASSERTIONS == 1
//     assert(GreatestCommonDivisor(B, t) == 1 && "B and t must be coprime for the modular inverse to exist");
//     #endif
//     for (uint32_t k = 0; k < ell; k++) {
//         // TODO: Optimize; keep Bk outsde the loop and just do Bk = Bk.ModMul(b, t);
//         NativeInteger Bk(1); for (uint32_t j = 0; j <= k; j++) Bk = Bk.ModMul(b, t);
//         int64_t Bk_inv = Bk.ModInverse(t).ConvertToInt<uint64_t>();
//         // Reduce to centered representation [-t/2, t/2] // (TODO: unnecessary!)
//         if (Bk_inv > bound) Bk_inv -= (bound << 1); // -= t_int
//         std::vector<int64_t> scalar(ell, Bk_inv);        
//         auto pt   = this->MakePackedPlaintext(scalar);
//         result[k] = this->EvalMult(ct, pt);
//     }
//     return result;
// }