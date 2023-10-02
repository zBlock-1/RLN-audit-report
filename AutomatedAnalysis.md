## Automated program analysis tools

Over the course of the audit, in addition to a manual review of the code, we applied different automated program analysis tools and evaluated their output.

1. [circomspect](#1-circomspect)
2. [Ecne](#2-ecne)

A note on results from Ecne:

- Ecne can output false positive. 
- It relies on static analysis and there is no solver to concretely find the potential attack vector.

### Results

The relevant findings from each tool were already included in the report. Below you can find their full output.

### 1. Circomspect 

[circomspect : A static analyzer and linter for the Circom zero-knowledge DSL](https://github.com/trailofbits/circomspect)

```
circomspect: analyzing template 'RLN'
note: Field element arithmetic could overflow, which may produce unexpected results.
   ┌─ /home/testadmin/Desktop/zk/rln/circom-rln/circuits/rln.circom:34:11
   │
34 │     y <== identitySecret + a1 * x;
   │           ^^^^^^^^^^^^^^^^^^^^^^^ Field element arithmetic here.
   │
   = For more details, see https://github.com/trailofbits/circomspect/blob/main/doc/analysis_passes.md#field-element-arithmetic.

circomspect: 1 issue found.

circomspect: analyzing template 'RangeCheck'
note: Comparisons with field elements greater than `p/2` may produce unexpected results.
   ┌─ /home/testadmin/Desktop/zk/rln/circom-rln/circuits/utils.circom:37:12
   │
37 │     assert(LIMIT_BIT_SIZE < 253);
   │            ^^^^^^^^^^^^^^^^^^^^ Field element comparison here.
   │
   = Field elements are always normalized to the interval `(-p/2, p/2]` before they are compared.
   = For more details, see https://github.com/trailofbits/circomspect/blob/main/doc/analysis_passes.md#field-element-comparison.

warning: Intermediate signals should typically occur in at least two separate constraints.
   ┌─ /home/testadmin/Desktop/zk/rln/circom-rln/circuits/utils.circom:42:5
   │
42 │     signal bitCheck[LIMIT_BIT_SIZE] <== Num2Bits(LIMIT_BIT_SIZE)(messageId);
   │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   │     │
   │     The intermediate signal array `bitCheck` is declared here.
   │     The intermediate signals in `bitCheck` are constrained here.
   │
   = For more details, see https://github.com/trailofbits/circomspect/blob/main/doc/analysis_passes.md#under-constrained-signal.

warning: Using `Num2Bits` to convert field elements to bits may lead to aliasing issues.
   ┌─ /home/testadmin/Desktop/zk/rln/circom-rln/circuits/utils.circom:42:41
   │
42 │     signal bitCheck[LIMIT_BIT_SIZE] <== Num2Bits(LIMIT_BIT_SIZE)(messageId);
   │                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Circomlib template `Num2Bits` instantiated here.
   │
   = Consider using `Num2Bits_strict` if the input size may be >= than the prime size.
   = For more details, see https://github.com/trailofbits/circomspect/blob/main/doc/analysis_passes.md#non-strict-binary-conversion.

circomspect: analyzing template 'MerkleTreeInclusionProof'
circomspect: 3 issues found.

circomspect: analyzing template 'Withdraw'
warning: The signal `address` is not used by the template.
  ┌─ /home/testadmin/Desktop/zk/rln/circom-rln/circuits/withdraw.circom:7:5
  │
7 │     signal input address;
  │     ^^^^^^^^^^^^^^^^^^^^ This signal is unused and could be removed.
  │
  = For more details, see https://github.com/trailofbits/circomspect/blob/main/doc/analysis_passes.md#unused-variable-or-parameter.

circomspect: 1 issue found.
~~~
```

### 2. Ecne

[Ecne: An engine for verifying the soundness of R1CS constraints](https://github.com/franklynwang/EcneProject)

The Circom circuits were compiled to non-optimized R1CS constraints system and then they were tested for `Weak Verification` to check for any bad constraints or underconstraints. All the circuits passed the Ecne tests without any bad or underconstraints. This verifies that R1CS equations of the given circuits uniquely determine outputs given inputs (i.e. that the constraints are sound).
