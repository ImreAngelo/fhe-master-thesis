# Mirrored OpenFHE internals

[ RUN      ] RGSW.inv
  [timing] Encrypt RGSW: 58.59 ms
  [timing] External Product: 69.43 ms
  [timing] Internal Product: 252.08 ms
  [timing] External Product: 40.85 ms
  [timing] EvalMultPlain RGSW: 10.05 ms
  [timing] External Product: 48.66 ms
[       OK ] RGSW.inv (602 ms)
[ RUN      ] RGSW.max
  [timing] Encrypt RGSW: 58.99 ms
  [timing] External Product: 57.14 ms
  [timing] Internal Product: 214.26 ms
  [timing] External Product: 50.57 ms
  [timing] EvalMultPlain RGSW: 10.00 ms
  [timing] External Product: 37.73 ms
[       OK ] RGSW.max (530 ms)


# Direct call to OpenFHE internals

[ RUN      ] RGSW.inv
  [timing] Encrypt RGSW: 59.99 ms
  [timing] External Product: 28.61 ms
  [timing] Internal Product: 320.70 ms
  [timing] External Product: 55.52 ms
  [timing] EvalMultPlain RGSW: 9.24 ms
  [timing] External Product: 71.17 ms
[       OK ] RGSW.inv (658 ms)
[ RUN      ] RGSW.max
  [timing] Encrypt RGSW: 57.55 ms
  [timing] External Product: 59.14 ms
  [timing] Internal Product: 157.85 ms
  [timing] External Product: 68.44 ms
  [timing] EvalMultPlain RGSW: 9.30 ms
  [timing] External Product: 129.52 ms
[       OK ] RGSW.max (581 ms)


# Further optimizations

[ RUN      ] RGSW.inv
  [timing] Encrypt RGSW: 59.86 ms
  [timing] External Product: 31.68 ms
  [timing] Internal Product: 254.41 ms
  [timing] External Product: 20.62 ms
  [timing] EvalMultPlain RGSW: 8.78 ms
  [timing] External Product: 79.87 ms
[       OK ] RGSW.inv (565 ms)
[ RUN      ] RGSW.max
  [timing] Encrypt RGSW: 59.42 ms
  [timing] External Product: 47.27 ms
  [timing] Internal Product: 112.83 ms
  [timing] External Product: 24.07 ms
  [timing] EvalMultPlain RGSW: 9.23 ms
  [timing] External Product: 87.34 ms
[       OK ] RGSW.max (451 ms)


# BV-RNS Gadget
Benchmark                            Time             CPU   Iterations
----------------------------------------------------------------------
RGSW/Encrypt_mean                0.700 ms        0.688 ms           10
RGSW/Encrypt_median              0.704 ms        0.681 ms           10
RGSW/Encrypt_stddev              0.017 ms        0.018 ms           10
RGSW/Encrypt_cv                   2.48 %          2.56 %            10
RGSW/ExternalProduct_mean        0.884 ms        0.879 ms           10
RGSW/ExternalProduct_median      0.888 ms        0.875 ms           10
RGSW/ExternalProduct_stddev      0.031 ms        0.013 ms           10
RGSW/ExternalProduct_cv           3.48 %          1.51 %            10
RGSW/InternalProduct_mean         5.24 ms         5.27 ms           10
RGSW/InternalProduct_median       5.27 ms         5.25 ms           10
RGSW/InternalProduct_stddev      0.123 ms        0.047 ms           10
RGSW/InternalProduct_cv           2.34 %          0.90 %            10