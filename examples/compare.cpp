#include "openfhe.h"

using namespace lbcrypto;


// Return wether x > 0, given that |a| < 1, by mapping x_i -> {0, 1}
template <typename T>
Ciphertext<T> compare(CryptoContext<T> cc, Ciphertext<T> x, uint32_t iterations = 1)
{
    // TODO: Create cryptocontext idependently

    // Converges to sign(x)
    for(uint32_t i = 0; i < iterations; i++) {
        auto a = cc->EvalMult(x, 0.5);
        auto b = cc->EvalMult(x, x);
        b = cc->EvalSub(3, b);
        x = cc->EvalMult(a, b);
    }
    
    // Map to {0, 1}
    cc->EvalAddInPlace(x, 1.0);
    cc->EvalMultInPlace(x, 0.5);

    return x;
}

// Return MSE between two vectors
template <typename T>
inline T mean_square_error(std::vector<T> a, std::vector<T> b)
{
    T error = 0;
    for(std::size_t i = 0; i < a.size(); i++) {
        auto e = (a[i] - b[i])/2;
        error += e*e;
    } 
    return error;
}

// Convert plaintext to vector of bools
template <typename T>
inline std::vector<bool> boolify(std::vector<T> & vec, T threshold = 0.5) 
{
    std::vector<bool> out;
    out.reserve(vec.size());

    // x[i] >= 0.5
    std::transform(vec.begin(), vec.end(), std::back_inserter(out), [threshold](T d) -> bool {
        return d >= threshold;
    });

    return out;
}


int main()
{
    // Params from example "simple real numbers"
    uint32_t multDepth = 8;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 4;
    
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    
    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;
    
    // Generate encryption keys
    auto keys = cc->KeyGen();
    
    // Relinearization key
    cc->EvalMultKeyGen(keys.secretKey); 

    // Encoding and encryption
    std::vector<double> x = { 0.25, -0.9, 0.8, -0.25 };
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(x);
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    std::cout << "Input: " << plaintext << std::endl;

    // Results
    std::vector<double> answer = { 1, 0, 1, 0 };
    std::vector<double> res;
    res.reserve(answer.size());

    // Convert to vector of {0, 1}
    for(uint32_t i = 1; i <= (multDepth - 1)/2; i++)
    {
        auto ci = compare(cc, ciphertext, i);
        
        Plaintext result;
        cc->Decrypt(keys.secretKey, ci, &result);
    
        result->SetLength(batchSize);
    
        std::cout.precision(5);
        std::cout << i << " iterations - " << "Output: " << result;

        res = result->GetRealPackedValue();
        
        // Mean squared error
        auto err = mean_square_error(answer, res);
        std::cout << "Error: " << err << std::endl;
    }

    std::cout << "Final result: [ ";
    for (auto b : boolify(res)) std::cout << (b ? "1" : "0") << " ";
    std::cout << "]" << std::endl;

    return 0;
}
