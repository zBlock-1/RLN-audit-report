# yAcademy Rate Limiting Nullifier (RLN)

Review Resources:

- [circom-rln](https://github.com/Rate-Limiting-Nullifier/circom-rln)

Auditors:

- [0xKitetsu](https://twitter.com/0xKitetsu)
- [0xnagu](https://github.com/thogiti)
- [Antonio Viggiano](https://github.com/aviggiano)
- [curiousapple](https://github.com/abhishekvispute)
- [Chen Wen Kang](https://github.com/cwkang1998)
- [Elpacos](https://github.com/Elpacos)
- [gafram](https://github.com/gafram)
- [Igor Line](https://github.com/igorline)
- [lwltea](https://github.com/lwltea)
- [MarkuSchick](https://github.com/MarkuSchick)
- [nullity](https://github.com/nullity00)
- [Oba](https://github.com/obatirou)
- [parsley](https://github.com/bbresearcher)
- [Rajesh Kanna](https://github.com/RajeshRk18)
- [Vincent Owen](https://github.com/makluganteng)
- [Vishal Kulkarni](https://github.com/Vishalkulkarni45)
- [whoismatthewmc](https://github.com/whoismatthewmc1)
- [zkoranges](https://github.com/zkoranges)

## Table of Contents

- [Review Summary](#review-summary)
- [Scope](#scope)
- [Code Evaluation Matrix](#code-evaluation-matrix)
- [Findings Explanation](#findings-explanation)
    - [Critical Findings](#critical-findings)
        - [1. Risk of secret getting revealed if the input is zero](#1-critical---risk-of-secret-getting-revealed-if-the-input-is-zero)
    - [High Findings](#high-findings)
    - [Medium Findings](#medium-findings)
        - [1. Unused public inputs optimized out by the circom compiler](#1-medium---unused-public-inputs-optimized-out-by-the-circom-compiler)
        - [2. Effective stake at risk is only fees and not the complete stake as intended](#2-medium---effective-stake-at-risk-is-only-fees-and-not-the-complete-stake-as-intended)
    - [Low Findings](#low-findings)
        - [1. Inconsistency between contract and circuit on the number of bits for userMessageLimit](#1-low---inconsistency-between-contract-and-circuit-on-the-number-of-bits-for-usermessagelimit)
        - [2. Difference between documents and implementation](#2-low---difference-between-documents-and-implementation)
        - [3. Unnecessary import & inheritance of Ownable](#3-low---unnecessary-import--inheritance-of-ownable)
        - [4. Edge case in user registration](#4-low---edge-case-in-user-registration)
        - [5. Parameter validation missing in rln.circom](#5-low---parameter-validation-missing-in-rlncircom)
        - [6. Check if the `identityCommitment` is less than the SCALAR FIELD](#6-low---check-if-the-identitycommitment-is-less-than-the-scalar-field)
        - [7. Specification uses incorrect definition of identity commitment](#7-low---specification-uses-incorrect-definition-of-identity-commitment)
    - [Informational Findings](#informational-findings)
        - [1. Mismatch between specification and implementation for x value](#1-informational---mismatch-between-specification-and-implementation-for-x-value)
        - [2. Misleading Naming Convention for Utility Circuits](#2-informational---misleading-naming-convention-for-utility-circuits)
        - [3. Edge case in Shamir Secret Sharing computation](#3-informational---edge-case-in-shamir-secret-sharing-computation)
        - [4. Possibility of Spamming](#4-informational---possibility-of-spamming)
        - [5. Penalty enforced on the user doesn't scale with the magnitude of their spam](#5-informational---penalty-enforced-on-the-user-doesnt-scale-with-the-magnitude-of-their-spam)
- [Final Remarks](#final-remarks)
- [Automated Program Analysis](/AutomatedAnalysis.md)

## Review Summary

**Rate Limiting Nullifier**

RLN (Rate-Limiting Nullifier) is a zk-gadget/protocol that enables spam prevention mechanism for anonymous environments.

Users register an identityCommitment, which is stored in a Merkle tree, along with a stake. When interacting with the protocol, the user generate a zero knowledge proof that ensures their identity commitment is part of the membership Merkle tree and they have not exceeded their rate limit. It leverages Shamir secret sharing for that. If they exceed their rate limit, their secret is revealed and their stake can be slashed.

The circuits of [RLN](https://github.com/Rate-Limiting-Nullifier/circom-rln/tree/37073131b9c5910228ad6bdf0fc50080e507166a) were reviewed over 15 days. The code review was performed between 31st May and 14th June, 2023. The repository was not under active development during the review, but the review was limited to the latest commit at the start of the review. This was commit [37073131b9](https://github.com/Rate-Limiting-Nullifier/circom-rln/tree/37073131b9c5910228ad6bdf0fc50080e507166a) for the circom-rln repo.

In addition, the contracts of the rln-contracts repo, commit [dfcdb2beff](https://github.com/Rate-Limiting-Nullifier/rln-contracts/tree/dfcdb2beff91583d02636570242cfdd8469b61c1), were provided as a reference implementation on how the circuits would be integrated. Although these contracts were considered out of scope, we have also included some related findings in this report.

## Scope

The scope of the review consisted of the following circuits at the specific commit:

- rln.circom
- utils.circom
- withdraw.circom

After the findings were presented to the RLN team, fixes were made and included in several PRs.

This review is a code review to identify potential vulnerabilities in the code. The reviewers did not investigate security practices or operational security and assumed that privileged accounts could be trusted. The reviewers did not evaluate the security of the code relative to a standard or specification. The review may not have identified all potential attack vectors or areas of vulnerability.

yAcademy and the auditors make no warranties regarding the security of the code and do not warrant that the code is free from defects. yAcademy and the auditors do not represent nor imply to third parties that the code has been audited nor that the code is free from defects. By deploying or using the code, RLN and users of the contracts agree to use the code at their own risk.

## Code Evaluation Matrix
---

| Category                 | Mark    | Description |
| ------------------------ | ------- | ----------- |
| Access Control           | N/A | RLN is a permissionless protocol, and as such no access control is required |
| Mathematics              | Good | Well known libraries such as circomlib were used whenever possible. In particular to calculate the Poseidon hash function of necessary parameters |
| Complexity               | Good | The code is easy to understand and closely follows the specification |
| Libraries                | Good | Well known libraries such as circomlib were used whenever possible |
| Decentralization         | Good | RLN is a permissionless protocol |
| Cryptography           | Good    | The docs recommend generating proofs using Groth16 using a BN254 curve, which has a security level of `128 bits`. It makes use of the Poseidon hash function known for its efficiency, simplicity, and resistance against various cryptanalytic attacks. However, it's essential to note that cryptographic algorithms and functions are always subject to ongoing analysis, and new attacks or weaknesses may be discovered in the future. |
| Code stability           | Good   | The code was reviewed at a specific commit. The code did not changed during the review. Moreover, it is not likely to change significantly with the addition of features or updates |
| Documentation            | Good | RLN documentation comprises a specification [RFC](https://rfc.vac.dev/spec/32/#32rln-v1), a Github documentation [website](https://rate-limiting-nullifier.github.io/rln-docs/), a Github [README](https://github.com/Rate-Limiting-Nullifier/circom-rln/blob/37073131b9c5910228ad6bdf0fc50080e507166a/README.md), and a [Hackmd presentation](https://hackmd.io/@AtHeartEngineer/ryw64YQUh#/). It is recommended to reduce the number of resources necessaries to fully understand the protocol |
| Monitoring               | N/A | The protocol is intended to be implemented by a dapp, which will be responsible for the monitoring |
| Testing and verification | Average | The protocol contains only a few tests for the circuits. It is recommended to add more tests to increase the test coverage |

## Findings Explanation

Findings are broken down into sections by their respective Impact:
 - Critical, High, Medium, Low Impact
     - These are findings that range from attacks that may cause loss of funds, a break in the soundness, zero-knowledge, completeness of the system, proof malleability, or cause any unintended consequences/actions that are outside the scope of the requirements
 - Informational
     - Findings including Recommendations and best practices

---

## Critical Findings

### 1. Critical - Risk of secret getting revealed if the input is zero

When the message `x` is given the value 0, the identity secret is revealed. 
#### Technical Details

If the input x is 0 in ``y <== identitySecret + a1 * x;``, it will reveal the ``identitySecret``. `x` becomes 0 for value 0 and `21888242871839275222246405745257275088548364400416034343698204186575808495617`
[Ref: Circom Docs](https://docs.circom.io/background/background/#signals-of-a-circuit)

Also, Circom 2.0.6 introduces two new prime numbers to work with : 
- The order of the scalar field of `BLS12 - 381` is ``52435875175126190479447740508185965837690552500527637822603658699938581184513``
- The goldilocks prime `18446744069414584321`, originally used in `plonky-2`

```
template RLN() {
    ...
    signal output y;
    ...
    y <== identitySecret + a1 * x;
    ...
}
```

#### Impact

The user may get his secret revealed without even violating any rules.

#### Recommendation

1. Try hashing the random number instead of directly using it.
2. Have a `greater_than` constraint that checks whether the x is greater than zero (Quite inefficient compared to 1).
3. Impose `greater_than` constraint / hash the random number outside of circuit (relatively more efficient).
4. Constrain `a1*x` to be non-zero by adding ``isZero(a1*x).out === 0``

#### Developer Response

> x is hash of the message, and it's hashed outside of the circuits. Probability of finding preimage of 0 for Poseidon hash is negligible, it's not critical bug; though it may be user error to use 0 value for x, but as it's public input - then it can be checked on the client side - no deal to make it in the circuit.

Reported by [Rajesh Kanna](https://github.com/RajeshRk18), [0xKitetsu](https://twitter.com/0xKitetsu), [Chen Wen Kang](https://github.com/cwkang1998), [Vincent Owen](https://github.com/makluganteng), [Antonio Viggiano](https://github.com/aviggiano), [Igor Line](https://github.com/igorline), [Oba](https://github.com/obatirou), [0xnagu](https://github.com/thogiti)


## High Findings

None

## Medium Findings

### 1. Medium - Unused public inputs optimized out by the circom compiler

The circuit ``withdraw.circom`` contains a potential issue related to public inputs being optimized out by the circom compiler.

#### Technical Details

The `withdraw.circom` circuit specifies `address` as a public input but does not use this input in any constraints. Consequently, the unused input could be pruned by the compiler, making the zk-SNARK proof independent of this input. This may result in a potentially exploitative behavior.
#### Impact

Medium. Despite circom not generating constraints for unused inputs, snarkjs, which is used by RLN, does generate these constraints. The protocol also tested ark-circom, which also adds the constraint ommitted by circom. However, if some zk-SNARK implementation does not include these constraints, this can lead to a potential loss of funds by users of the protocol.

#### Recommendation

As outlined in [0xPARC's zk-bug-tracker](https://github.com/0xPARC/zk-bug-tracker#5-unused-public-inputs-optimized-out), it is advised to add a dummy constraint using the unused signal address in the circuit. This change ensures that the zk-SNARK proof is dependent on the `address` input.

```diff
diff --git a/circuits/withdraw.circom b/circuits/withdraw.circom
index a2051ea..7a4b88d 100644
--- a/circuits/withdraw.circom
+++ b/circuits/withdraw.circom
@@ -6,6 +6,8 @@ template Withdraw() {
     signal input identitySecret;
     signal input address;
 
+    signal addressSquared <== address * address;
+
     signal output identityCommitment <== Poseidon(1)([identitySecret]);
 }
```

#### Developer Response
> Good find! We'll add the "dummy constraint" to the circuit.

Reported by [Antonio Viggiano](https://github.com/aviggiano), [Igor Line](https://github.com/igorline), [Oba](https://github.com/obatirou), [Chen Wen Kang](https://github.com/cwkang1998), [Vincent Owen](https://github.com/makluganteng), [0xKitetsu](https://twitter.com/0xKitetsu), [MarkuSchick](https://github.com/MarkuSchick), [Elpacos](https://github.com/Elpacos), [gafram](https://github.com/gafram), [Rajesh Kanna](https://github.com/RajeshRk18), [curiousapple](https://github.com/abhishekvispute), [0xnagu](https://github.com/thogiti), [lwltea](https://github.com/lwltea), [parsley](https://github.com/bbresearcher), [Vishal Kulkarni](https://github.com/Vishalkulkarni45), [whoismatthewmc](https://github.com/whoismatthewmc1), [zkoranges](https://github.com/zkoranges)

### 2. Medium - Effective stake at risk is only fees and not the complete stake as intended


RLN contracts enforce users to stake and register themselves before being part of the network.
The idea here is if a user misbehaves and spams the network, anyone can slash them in return for their stake.
However, since networks are anonymous, users can slash themselves using another identity and only lose fees.

#### Technical Details

`N/A`
#### Impact
Users lose only part of the stake for their misbehavior

#### Recommendation
Consider using different incentive mechanism for slash.
#### Developer Response
Acknowledged

Reported by [curiousapple](https://github.com/abhishekvispute)

## Low Findings

### 1. Low - Inconsistency between contract and circuit on the number of bits for userMessageLimit

There is an inconsistency between the `RLN.sol` and `rln.circom` pertaining to the `userMessageLimit`. Specifically, the difference lies in the range of values that `messageLimit`, `messageId`, and `userMessageLimit` can take.

#### Technical Details

In `RLN`.sol, the calculation of `messageLimit` is based on the amount divided by `MINIMAL_DEPOSIT`. Given the current implementation, `messageLimit` has the potential to accept values up to `2**256 - 1`.

```
uint256 messageLimit = amount / MINIMAL_DEPOSIT;
```

On the other hand, in `rln.circom`, the `messageId` and `userMessageLimit` values are limited by the `RangeCheck(LIMIT_BIT_SIZE)` function to `2**16 - 1`.

```
template RLN(DEPTH, LIMIT_BIT_SIZE) {
...
    // messageId range check
    RangeCheck(LIMIT_BIT_SIZE)(messageId, userMessageLimit);
...
}
component main { public [x, externalNullifier] } = RLN(20, 16);
```

Although the contracts check that the identity commitment is lower than the size of the set, which is `2**20`, it is possible that the `DEPTH` and `LIMIT_BIT_SIZE` parameters of the circuit are modified, which would lead to unexpected outcomes if not addressed.

#### Impact
Low. On the current implementation, this discrepancy does not pose any issues to the protocol.

#### Recommendation

Short term, add a range check to the circuits to make sure they are constrained to the same range as the smart contract variables. Long term, make sure the input space of the contracts and the circuits are always in sync.

```diff
function register(uint256 identityCommitment, uint256 amount) external {
        ...
        uint256 messageLimit = amount / MINIMAL_DEPOSIT;
+       require( messageLimit <= type(uint16).max , "Max amount of message limit is 65535");
        token.safeTransferFrom(msg.sender, address(this), amount);
        ...
    }
```

#### Developer Response
> Good find! We'll add this check to the contract :)

Reported by [nullity](https://github.com/nullity00), [Antonio Viggiano](https://github.com/aviggiano), [Igor Line](https://github.com/igorline), [Oba](https://github.com/obatirou), [curiousapple](https://github.com/abhishekvispute), [0xnagu](https://github.com/thogiti), [Vishal Kulkarni](https://github.com/Vishalkulkarni45)

### 2. Low - Difference between documents and implementation

The documantation mentions that the rate limit is between `1` and `userMessageLimit`

> Signaling will use other circuit, where your limit is private input, and the counter k is checked that it's in the range from 1 to userMessageLimit.

Although the implementation is sound, the counter `k` should be documented as being between `0` to `userMessageLimit-1`
Testing the circuit allows for a `messageId` of `0` and does not allow for a `messageId` of `userMessageLimit`.

#### Technical Details

```
signal rangeCheck <== LessThan(LIMIT_BIT_SIZE)([messageId, limit]);
```
The above code will always return true for a `messageId` of `0`

#### Impact
Low. There is no impact except for clarity to potential developers/users.

#### Recommendation
The project may consider chaging the wording to be something like :
```
Signaling will use other circuit, where your limit is private input, and the counter k is checked that it's in the range from 0 to userMessageLimit -1.
```

#### Developer Response
> Docs are out of date, we'll update them soon.

Reported by [lwltea](https://github.com/lwltea), [parsley](https://github.com/bbresearcher), [Vishal Kulkarni](https://github.com/Vishalkulkarni45), [whoismatthewmc](https://github.com/whoismatthewmc1), [zkoranges](https://github.com/zkoranges)

### 3. Low - Unnecessary import & inheritance of Ownable

Contract RLN inherits from Ownable but ownable functionality isn't actually used by the contract.

#### Technical Details

There are imports and inheritance for `Ownable` in the `RLN.sol` contract. Ownable is never used within the RLN contract.

#### Impact
Low.

#### Recommendation
Remove `Ownable` import and inheritance from `RLN.sol`

#### Developer Response
> Thanks, we should remove Ownable from the contract.

Reported by [curiousapple](https://github.com/abhishekvispute), [lwltea](https://github.com/lwltea)

### 4. Low - Edge case in user registration

In the user registration the calculation `y = mx + c` can have unexpected side effects.

#### Technical Details

In the [user registration spec](https://rate-limiting-nullifier.github.io/rln-docs/protocol_spec.html#user-registration), for `y = mx + c` where `m` and `x` can be multiplicative inverse of each other(less probability),then the eq becomes `y = 1 + c` the attacker can easily subtract from the public `y` to get hash of the secret key.
#### Impact
Low.

#### Recommendation
In the `rln.circom` add a check to make sure `m` and `x` are not multiplicative inverse values of each other.

#### Developer Response
> The probability of that is negligible, and prover can make this check before proving.

Reported by [Vishal Kulkarni](https://github.com/Vishalkulkarni45)
### 5. Low - Parameter validation missing in rln.circom

The code doesn't check if `DEPTH` and `LIMIT_BIT_SIZE` are within expected ranges or conform to specific requirements. If these are passed in as invalid values, it could lead to unexpected behavior or vulnerabilities.

#### Technical Details

```
template RLN(DEPTH, LIMIT_BIT_SIZE) {
```

Missing range checks for `DEPTH` and `LIMIT_BIT_SIZE`
#### Impact
Low.

#### Recommendation
Add checks to ensure that the values of `DEPTH` and `LIMIT_BIT_SIZE` are within expected ranges.

#### Developer Response
> `DEPTH` and `LIMIT_BIT_SIZE` are not the inputs of the circuit, but compile-time metaparameters. We don't need to range check them. It's just constant values that describe behavior of the circuit as well as code itself.

Reported by [0xnagu](https://github.com/thogiti), [zkoranges](https://github.com/zkoranges)

### 6. Low - Check if the `identityCommitment` is less than the SCALAR FIELD

As mentioned in [0xparc's bug tracker](https://github.com/0xPARC/zk-bug-tracker#semaphore-1), the inputs have to be less than the Snark's Scalar Field.

#### Technical Details

The prime field in circom is ~ `2**254` whereas solidity supports 256-bit integers. There is a possibility of users registering twice, once using the `identityCommitment` & another  time using `A` such that `A mod p = identityCommitment` where `p` is the prime field of circom. Here, the user registers twice using the same `identitySecret`.

#### Impact
Low.

#### Recommendation
Add check to ensure that user doesn't register twice with the same secret.
```
require(identityCommitment < snark_scalar_field);
```

#### Developer Response
> `identityCommitment` cannot be 256 bit, as it's the result of Poseidon hash-function that's defined over p (prime field of Circom/bn254)

Reported by [nullity](https://github.com/nullity00)

### 7. Low - Specification uses incorrect definition of identity commitment

The [V2 Specification](https://rfc.vac.dev/spec/58/#rln-diff-flow) uses the `identity_secret` to compute the `identity_commitment` instead of the `identity_secret_hash`. The `identity_secret` is already used by the Semaphore circuits and should not get revealed in a Slashing event.

#### Technical Details

RLN [stays compatible](https://rfc.vac.dev/spec/32/#appendix-b-identity-scheme-choice) with Semaphore circuits by deriving the secret ("`identity_secret_hash`") as the hash of the semaphore secrets `identity_nullifier` and `identity_trapdoor`.

RLN V2 improves upon the V1 Protocol by allowing to set different rate-limits for users.
Hence, the definition of the user identity changes from the [V1 definition](https://rfc.vac.dev/spec/32/#user-identity):

```diff
    identity_secret: [identity_nullifier, identity_trapdoor],
    identity_secret_hash: poseidonHash(identity_secret),
    identity_commitment: poseidonHash([identity_secret_hash])
+   rate_commitment: poseidonHash([identity_commitment, userMessageLimit])
```
The [RLN-Diff](https://rfc.vac.dev/spec/58/#rln-diff-flow) flow wrongfully derives the `identity_commitment` from the `identity_secret` directly instead of the `identity_secret_hash`.
#### Impact
Low.

#### Recommendation

In Short term, Modify the following part of the [V2 Specification](https://rfc.vac.dev/spec/58/#registration-1) :

```diff
Registration

-id_commitment in 32/RLN-V1 is equal to poseidonHash=(identity_secret). 
+id_commitment in 32/RLN-V1 is equal to poseidonHash=(identity_secret_hash). 
The goal of RLN-Diff is to set different rate-limits for different users. It follows that id_commitment must somehow depend on the user_message_limit parameter, where 0 <= user_message_limit <= message_limit. There are few ways to do that:
1. Sending identity_secret_hash = poseidonHash(identity_secret, userMessageLimit) 
and zk proof that user_message_limit is valid (is in the right range). This approach requires zkSNARK verification, which is an expensive operation on the blockchain.
-2. Sending the same identity_secret_hash as in 32/RLN-V1 (poseidonHash(identity_secret)) 
+2. Sending the same identity_commitment as in 32/RLN-V1 (poseidonHash(identity_secret_hash)) 
and a user_message_limit publicly to a server or smart-contract where 
-rate_commitment = poseidonHash(identity_secret_hash, userMessageLimit) is calculated. 
+rate_commitment = poseidonHash(identity_commitment, userMessageLimit) is calculated. 
The leaves in the membership Merkle tree would be the rate_commitments of the users. This approach requires additional hashing in the Circuit, but it eliminates the need for zk proof verification for the registration.
```

In the long term, rename the variable `identity_secret` in the circuit to avoid further confusion with a variable of the same name [derived from Semaphore](https://rfc.vac.dev/spec/32/#appendix-b-identity-scheme-choice).

#### Developer Response
> Spec/docs is out of date, we'll update it soon. Thanks for your review.

Reported by [MarkuSchick](https://github.com/MarkuSchick)

## Informational Findings

### 1. Informational - Mismatch between specification and implementation for x value

Mismatch between specification and implementation regarding the `x` message value.

#### Technical Details

In [58/RLN-V2](https://rfc.vac.dev/spec/58/#proof-generation), the specification states that `x` is the signal hashed. However, in the `rln.circom` circuit, `x` is the message without hash.

#### Impact
Informational.

#### Recommendation

Update the implementation to hash the `x` value according to the specification.

#### Developer Response
> x is hash of the message, and it's hashed outside of the circuits. Correctness can be checked on the client-side as it's public input.

Reported by [Antonio Viggiano](https://github.com/aviggiano), [Igor Line](https://github.com/igorline), [Oba](https://github.com/obatirou)

### 2. Informational - Misleading Naming Convention for Utility Circuits

The `withdraw.circom` does not involve the generation of a proof to withdraw funds from the contract. Instead, it is a utility circuit that is used to generate the identity commitment from a private identity hash. The naming of the circuit is misleading.

#### Technical Details

`N/A`

#### Impact
Informational.

#### Recommendation

Rename the circuit to `identity_commitment.circom` to better reflect its purpose.

#### Developer Response
None

Reported by [Chen Wen Kang](https://github.com/cwkang1998), [Vincent Owen](https://github.com/makluganteng)

### 3. Informational - Edge case in Shamir Secret Sharing computation

In Shamir Secret Sharing computation, the coefficient of the random value X may be a multiplicative inverse so the secret maybe revealed in that case. Although, the probability of having multiplicative inverse is $1/p$ where $p$ is prime order.

#### Technical Details

`N/A`

#### Impact
The user may get his secret revealed but the probability is negligible.

#### Recommendation

This finding is just to address this issue. If the secret sharing is computed using higher degree polynomials, we may not have this issue.

#### Developer Response
> As you said - probability of that is negligible

Reported by [Rajesh Kanna](https://github.com/RajeshRk18)

### 4. Informational - Possibility of Spamming

By sending the same message continuously, users can still spam the network. It is true that if the users change their msg and go above the msg limit, they expose their secret, however, they can still send the same messages continuously.

#### Technical Details

`N/A`

#### Impact
The protocol team cleared that this is not an issue, since nodes will filter the same msg out.

#### Recommendation

`N/A`

#### Developer Response
> You cannot spam more than once. As soon as user exceed the limit, they can be slashed immediately (at least on the node level)

Reported by [curiousapple](https://github.com/abhishekvispute)

### 5. Informational - Penalty enforced on the user doesn't scale with the magnitude of their spam

There is no difference between a penalty for spamming once or spamming x1000 times.
Hence the cost of attack does not scale with the impact
All attacker needs to do is do a minimum deposit and then he/she can spam the network with any number of messages at once, and all they are penalized for is a minimum deposit.

#### Technical Details
`N/A`
#### Impact
This incentive structure puts an innocent and malicious rule breaker in the same bucket.

#### Recommendation
`N/A`

#### Developer Response
> You cannot spam more than once. As soon as user exceed the limit, they can be slashed immediately (at least on the node level)

Reported by [curiousapple](https://github.com/abhishekvispute)


## Final remarks

- The RLN Protocol assumes that :
    - Poseidon hash fucntion is collision-resistant, resistant to differential, algebraic, and interpolation attacks.
    - The trusted setup will be done correctly and all relevant artifacts kept safe.
- The Merkle tree used for membership proof is assumed to be secure against second-preimage attacks.
- Social engineering attacks are still a valid way to break the system. An attacker can obtain the `identitySecret` signal of a user by using methods such as social engineering, phishing attacks, or exploiting vulnerabilities in the user's system.
- The security of the circuit also depends on the secrecy of the `identitySecret` signal, which is assumed to be kept secret by the user.
- The security of the circuit depends on the security of the cryptographic primitives used for range checks and SSS share calculations.
- Overall, the code demonstrates good implementation of mathematical operations and basic functionality. However, it could benefit from more extensive documentation and additional testing and verification procedures.
