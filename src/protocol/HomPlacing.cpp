#include "HomPlacing.hpp"
#include <iostream>
#include "testing/Timer.h"

#define TEST


namespace Server // should be "protocol"
{    
    using namespace testing;

    std::vector<CT> HomPlacing(const CC cc, const CT value, const std::vector<CT>& index_bits) 
    {
        const uint32_t L = index_bits.size();
        const uint32_t n = 1u << L;          // number of leaves = 2^L
        const uint32_t total = 2 * n - 1;    // total tree nodes

        // Allocate node array; only live nodes are set, rest remain null.
        std::vector<CT> b(total);

        // Root gets the value; all other nodes start at 0 (null CT, filled lazily).
        b[0] = value;

        Timer t("Algorithm 1 - HomPlacing");

        // Traverse level by level.
        for (uint32_t i = 0; i < L; i++) 
        {
            const CT& bit = index_bits[i]; // c_i

            for (uint32_t j = 0; j < (1u << i); j++) 
            {
                uint32_t parent_idx = (1u << i) - 1 + j;
                uint32_t left_idx   = (1u << (i + 1)) - 1 + 2 * j;
                uint32_t right_idx  = left_idx + 1;

                if (left_idx >= total || right_idx >= total)
                    throw std::out_of_range("HomPlacing: tree index overflow");

                const CT& parent = b[parent_idx];

                // right = parent * bit
                b[right_idx] = cc->EvalMult(parent, bit);
                // left  = parent - right  (= parent * (1 - bit))
                b[left_idx]  = cc->EvalSub(parent, b[right_idx]);
            }
        }

        // Extract leaves: b[n-1] .. b[2n-2]
        std::vector<CT> leaves(n);
        for (uint32_t i = 0; i < n; i++)
            leaves[i] = b[n - 1 + i];

        return leaves;
    }
}

int main() 
{
    using namespace lbcrypto;
    using namespace testing;

    std::cout << "Hello world!" << std::endl;

#ifdef TEST
{   
    Timer t("Full test");
    uint32_t depth = 3;

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;

    {
        Timer t("Generate crypto context");
        cc = GenCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
    }
    {
        Timer t("KeyGen + EvalMultKeyGen");
        keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
    }
    {

        Plaintext plaintext = cc->MakePackedPlaintext({ 10 });
        auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);
        
        std::vector<Ciphertext<DCRTPoly>> bits;
        auto target = 2; // target slot

        for (uint32_t k = 0; k < depth; k++) 
        {
            int64_t bit = (target >> (depth - 1 - k)) & 1u;
            bits.push_back(cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit})));
        }
        
        // Server
        auto res = Server::HomPlacing(cc, ciphertext, bits);

        // Client
        std::vector<int64_t> buckets;
        buckets.reserve(std::pow(2, depth));

        std::cout << "Placing: ";
        for(auto xi : res)
        {
            Plaintext pi;
            cc->Decrypt(keys.secretKey, xi, &pi);
            pi->SetLength(1);

            auto val = pi->GetPackedValue()[0];
            buckets.emplace_back(val);
            std::cout << val << " ";
        }

        std::cout << "\n";
    }
}
#endif

    return 0;
}