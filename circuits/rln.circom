pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template MerkleTreeInclusionProof(DEPTH) {
    signal input leaf;
    signal input pathIndex[DEPTH];
    signal input pathElements[DEPTH];

    signal output root;

    component mux[DEPTH];
    component hashers[DEPTH];
    signal levelHashes[DEPTH + 1];
    
    levelHashes[0] <== leaf;
    for (var i = 0; i < DEPTH; i++) {
        // pathIndex must be binary
        pathIndex[i] * (pathIndex[i] - 1) === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndex[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[DEPTH];
}

template RangeCheck(LIMIT_BIT_SIZE) {
    assert(LIMIT_BIT_SIZE < 253);

    signal input messageId;
    signal input limit;

    component bits = Num2Bits(LIMIT_BIT_SIZE);
    bits.in <== messageId;
    
    // make sure messageId < limit
    component lt = LessThan(LIMIT_BIT_SIZE);
    lt.in[0] <== messageId;
    lt.in[1] <== limit;
    lt.out === 1;
}


template RLN(DEPTH, LIMIT_BIT_SIZE) {
    // Private signals
    signal input identitySecret;
    signal input userMessageLimit;
    signal input messageId;
    signal input pathElements[DEPTH];
    signal input identityPathIndex[DEPTH];

    // Public signals
    signal input x;
    signal input externalNullifier;

    // Outputs
    signal output y;
    signal output root;
    signal output nullifier;

    component identityHasher = Poseidon(1);
    identityHasher.inputs[0] <== identitySecret;
    signal identityCommitment <== identityHasher.out;
    
    component rateHasher = Poseidon(2);
    rateHasher.inputs[0] <== identityCommitment;
    rateHasher.inputs[1] <== userMessageLimit;
    signal rateCommitment <== rateHasher.out;

    // Membership check
    component merkleProof = MerkleTreeInclusionProof(DEPTH);
    merkleProof.leaf <== rateCommitment;
    for (var i = 0; i < DEPTH; i++) {
        merkleProof.pathIndex[i] <== identityPathIndex[i];
        merkleProof.pathElements[i] <== pathElements[i];
    }
    root <== merkleProof.root;

    // messageId range check
    component rangeCheck = RangeCheck(LIMIT_BIT_SIZE);
    rangeCheck.messageId <== messageId;
    rangeCheck.limit <== userMessageLimit;

    // SSS share calculations
    component a1Hasher = Poseidon(3);
    a1Hasher.inputs[0] <== identitySecret;
    a1Hasher.inputs[1] <== externalNullifier;
    a1Hasher.inputs[2] <== messageId;
    signal a1 <== a1Hasher.out;
    
    y <== identitySecret + a1 * x;

    // nullifier calculation
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== a1;
    nullifier <== nullifierHasher.out;
}

component main { public [x, externalNullifier] } = RLN(20, 16);