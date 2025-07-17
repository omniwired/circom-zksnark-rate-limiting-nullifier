pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template MerkleTreeInclusion(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component hashers[levels];
    component selectors[levels];
    
    signal currentLevel[levels + 1];
    currentLevel[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        selectors[i] = MultiMux1(2);
        selectors[i].c[0][0] <== currentLevel[i];
        selectors[i].c[0][1] <== pathElements[i];
        selectors[i].c[1][0] <== pathElements[i];
        selectors[i].c[1][1] <== currentLevel[i];
        selectors[i].s <== pathIndices[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
        
        currentLevel[i + 1] <== hashers[i].out;
    }

    root === currentLevel[levels];
}


template RLN(levels) {
    // Public inputs
    signal input externalNullifier;    // Hash of (epoch, appId)
    signal input y;                    // Share value: y = a1 * x + a0
    signal input nullifier;            // Nullifier for rate limiting
    signal input root;                 // Merkle root of identity tree
    signal input signalHash;           // Hash of the signal/message

    // Private inputs
    signal input identitySecret;       // a0 - the secret key
    signal input pathElements[levels];  // Merkle proof elements
    signal input pathIndices[levels];   // Merkle proof indices
    signal input messageId;            // Message ID for this epoch

    // Intermediate signals
    signal a1;                         // a1 = Hash(identitySecret, externalNullifier)
    signal identityCommitment;         // identityCommitment = Hash(identitySecret)
    signal nullifierComputed;          // nullifier = Hash(a1, messageId)
    signal yComputed;                  // y = a1 * x + a0 (where x = signalHash)

    // Compute a1 = Hash(identitySecret, externalNullifier)
    component a1Hasher = Poseidon(2);
    a1Hasher.inputs[0] <== identitySecret;
    a1Hasher.inputs[1] <== externalNullifier;
    a1 <== a1Hasher.out;

    // Compute identity commitment = Hash(identitySecret)
    component identityHasher = Poseidon(1);
    identityHasher.inputs[0] <== identitySecret;
    identityCommitment <== identityHasher.out;

    // Verify membership in identity tree
    component merkleProof = MerkleTreeInclusion(levels);
    merkleProof.leaf <== identityCommitment;
    merkleProof.root <== root;
    for (var i = 0; i < levels; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }

    // Compute nullifier = Hash(a1, messageId)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== a1;
    nullifierHasher.inputs[1] <== messageId;
    nullifierComputed <== nullifierHasher.out;

    // Verify nullifier matches public input
    nullifier === nullifierComputed;

    // Compute y = a1 * signalHash + identitySecret
    // This is the RLN share: if two shares are published in the same epoch,
    // the secret key can be derived
    yComputed <== a1 * signalHash + identitySecret;

    // Verify y matches public input
    y === yComputed;

    // Constraint to prevent unconstrained signals
    signal dummy;
    dummy <== messageId * messageId;
}

component main {public [externalNullifier, y, nullifier, root, signalHash]} = RLN(20);