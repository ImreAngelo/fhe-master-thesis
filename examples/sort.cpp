#include "openfhe.h"

using namespace lbcrypto;

#define TEST_ONE
#ifdef TEST
#define TEST_ONE
#define TEST_TWO
#endif


// Compute minimax coefficients for domain [delta, 1]
// p(x) = c1*x + c3*x^3 approximates sign(x) on [delta, 1]
template <typename T>
Ciphertext<T> minimax_seed(CryptoContext<T> cc, Ciphertext<T> x, double delta)
{
    double S  = 1 + delta + delta*delta;
    double xs = std::sqrt(S / 3.0);
    double c3 = -6.0 / (2*S*xs + 3*(S - 1));
    double c1 = -c3 * S;

    // 2 ciphertext multiplications = 2 levels consumed
    auto x2     = cc->EvalMult(x, x);        // x²
    auto x3     = cc->EvalMult(x2, x);       // x³

    // scalar multiplications are free (no level consumed)
    auto result = cc->EvalMult(x,  c1);      // c₁x
    cc->EvalAddInPlace(result, cc->EvalMult(x3, c3));  // + c₃x³

    return result;
}

// Return wether x > 0 by mapping x_i -> {-1, 1}, 
// given that x is in [-1, -delta) U (delta, 1]
template <typename T>
Ciphertext<T> compare_minimax(CryptoContext<T> cc, Ciphertext<T> x, uint32_t iterations = 2, double delta = 0.001)
{
    // Seed minimax
    x = minimax_seed(cc, x, delta);

    // Newton's method iterations, converges to sign(x)
    for (uint32_t i = 0; i < iterations; i++) {
        auto a = cc->EvalMult(x, 0.5);
        auto b = cc->EvalMult(x, x);
        b = cc->EvalSub(3.0, b);
        x = cc->EvalMult(a, b);
    }
    
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
// Assume T = double unless explicitly set
template <typename T>
inline std::vector<bool> boolify(std::vector<T> & vec, T threshold = 0)
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
    std::vector<double> answer = { 1, -1, 1, -1 };
    std::vector<double> res;
    res.reserve(answer.size());

#ifdef TEST_ONE
    // Convert to vector of {-1, 1}
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
#endif

    std::cout << "Final result: [ ";
    for (auto b : boolify(res)) std::cout << (b ? "1" : "-1") << " ";
    std::cout << "]" << std::endl;

    return 0;
}
