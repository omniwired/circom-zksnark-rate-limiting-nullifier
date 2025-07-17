const snarkjs = require('snarkjs');
const circomlibjs = require('circomlibjs');
const fs = require('fs');
const path = require('path');

class RLNProof {
    constructor(proof, publicSignals) {
        this.proof = proof;
        this.publicSignals = publicSignals;
    }
    
    // Convert proof to Solidity format
    toSolidityProof() {
        return {
            a: [this.proof.pi_a[0], this.proof.pi_a[1]],
            b: [[this.proof.pi_b[0][1], this.proof.pi_b[0][0]], 
                [this.proof.pi_b[1][1], this.proof.pi_b[1][0]]],
            c: [this.proof.pi_c[0], this.proof.pi_c[1]]
        };
    }
    
    // Get formatted public signals
    getPublicSignals() {
        return {
            externalNullifier: this.publicSignals[0],
            y: this.publicSignals[1],
            nullifier: this.publicSignals[2],
            root: this.publicSignals[3],
            signalHash: this.publicSignals[4]
        };
    }
}

class RLNIdentity {
    constructor(secret) {
        this.secret = secret || this.generateSecret();
    }
    
    generateSecret() {
        // In a real implementation, use cryptographically secure random
        return BigInt(Math.floor(Math.random() * 2**253)).toString();
    }
    
    async getCommitment() {
        const poseidon = await circomlibjs.buildPoseidon();
        return poseidon.F.toObject(poseidon([this.secret])).toString();
    }
    
    async generateShare(externalNullifier, signalHash, messageId) {
        const poseidon = await circomlibjs.buildPoseidon();
        const F = poseidon.F;
        
        // Calculate a1 = Hash(identitySecret, externalNullifier)
        const a1 = F.toObject(poseidon([this.secret, externalNullifier]));
        
        // Calculate nullifier = Hash(a1, messageId)
        const nullifier = F.toObject(poseidon([a1, messageId]));
        
        // Calculate y = a1 * signalHash + identitySecret
        const y = F.toObject(F.add(F.mul(a1, signalHash), this.secret));
        
        return {
            a1: a1.toString(),
            nullifier: nullifier.toString(),
            y: y.toString()
        };
    }
    
    // Serialize identity for storage
    serialize() {
        return {
            secret: this.secret,
            type: 'RLNIdentity',
            version: '1.0'
        };
    }
    
    // Deserialize identity from storage
    static deserialize(data) {
        if (data.type !== 'RLNIdentity' || data.version !== '1.0') {
            throw new Error('Invalid identity data');
        }
        return new RLNIdentity(data.secret);
    }
}

class MerkleTree {
    constructor(levels, zero_value, leaves, hasher) {
        this.levels = levels;
        this.hasher = hasher;
        this.zero_values = [zero_value];
        this.leaves = leaves;
        
        for (let i = 1; i < levels; i++) {
            this.zero_values[i] = hasher([this.zero_values[i-1], this.zero_values[i-1]]);
        }
        
        this.layers = [leaves];
        this.buildTree();
    }
    
    buildTree() {
        for (let level = 0; level < this.levels - 1; level++) {
            const currentLevel = this.layers[level];
            const nextLevel = [];
            
            for (let i = 0; i < currentLevel.length; i += 2) {
                const left = currentLevel[i];
                const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : this.zero_values[level];
                nextLevel.push(this.hasher([left, right]));
            }
            
            this.layers.push(nextLevel);
        }
    }
    
    getRoot() {
        return this.layers[this.levels - 1][0];
    }
    
    getProof(index) {
        const proof = {
            pathElements: [],
            pathIndices: []
        };
        
        for (let level = 0; level < this.levels - 1; level++) {
            const position = index % 2;
            const levelIndex = Math.floor(index / 2);
            const currentLevel = this.layers[level];
            
            if (position === 0) {
                proof.pathElements.push(
                    levelIndex + 1 < currentLevel.length 
                        ? currentLevel[levelIndex * 2 + 1] 
                        : this.zero_values[level]
                );
            } else {
                proof.pathElements.push(currentLevel[levelIndex * 2]);
            }
            
            proof.pathIndices.push(position);
            index = Math.floor(index / 2);
        }
        
        return proof;
    }
    
    insert(leaf) {
        this.leaves.push(leaf);
        this.buildTree();
    }
}

class RLN {
    constructor(options = {}) {
        this.merkleTreeHeight = options.merkleTreeHeight || 20;
        this.wasmPath = options.wasmPath || path.join(__dirname, 'wasm/rln.wasm');
        this.zkeyPath = options.zkeyPath || path.join(__dirname, 'wasm/rln.zkey');
        this.vkeyPath = options.vkeyPath || path.join(__dirname, 'wasm/verification_key.json');
        
        this.poseidon = null;
        this.tree = null;
        this.identities = [];
    }
    
    async init() {
        console.log('🔧 Initializing RLN...');
        
        // Initialize Poseidon
        this.poseidon = await circomlibjs.buildPoseidon();
        
        // Initialize empty merkle tree
        this.tree = new MerkleTree(
            this.merkleTreeHeight,
            BigInt(0),
            [],
            (inputs) => this.poseidon.F.toObject(this.poseidon(inputs.map(x => this.poseidon.F.e(x))))
        );
        
        console.log('✅ RLN initialized successfully');
    }
    
    // Register a new identity
    async registerIdentity(identity) {
        const commitment = await identity.getCommitment();
        const index = this.identities.length;
        
        this.identities.push({
            identity,
            commitment,
            index
        });
        
        this.tree.insert(BigInt(commitment));
        
        return {
            index,
            commitment,
            root: this.tree.getRoot().toString()
        };
    }
    
    // Generate a proof for posting a message
    async generateProof(identityIndex, signal, externalNullifier, messageId) {
        if (!this.poseidon) await this.init();
        
        const identity = this.identities[identityIndex];
        if (!identity) {
            throw new Error('Identity not found');
        }
        
        // Hash the signal
        const signalHash = this.poseidon.F.toObject(this.poseidon([signal]));
        
        // Generate share
        const share = await identity.identity.generateShare(
            externalNullifier,
            signalHash,
            messageId
        );
        
        // Get merkle proof
        const merkleProof = this.tree.getProof(identityIndex);
        
        // Create witness
        const witness = {
            externalNullifier: externalNullifier.toString(),
            y: share.y,
            nullifier: share.nullifier,
            root: this.tree.getRoot().toString(),
            signalHash: signalHash.toString(),
            identitySecret: identity.identity.secret,
            pathElements: merkleProof.pathElements.map(e => e.toString()),
            pathIndices: merkleProof.pathIndices.map(i => i.toString()),
            messageId: messageId.toString()
        };
        
        // Generate proof
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            witness,
            this.wasmPath,
            this.zkeyPath
        );
        
        return new RLNProof(proof, publicSignals);
    }
    
    // Verify a proof
    async verifyProof(proof) {
        if (!fs.existsSync(this.vkeyPath)) {
            throw new Error('Verification key not found');
        }
        
        const vKey = JSON.parse(fs.readFileSync(this.vkeyPath, 'utf8'));
        return await snarkjs.groth16.verify(vKey, proof.publicSignals, proof.proof);
    }
    
    // Calculate external nullifier for epoch and app
    async calculateExternalNullifier(epoch, appId) {
        if (!this.poseidon) await this.init();
        
        return this.poseidon.F.toObject(this.poseidon([epoch, appId])).toString();
    }
    
    // Get current epoch
    getCurrentEpoch(epochLength = 3600) { // 1 hour epochs by default
        return Math.floor(Date.now() / 1000 / epochLength);
    }
    
    // Recover secret from two shares (for slashing)
    recoverSecret(share1, share2) {
        const { x: x1, y: y1 } = share1;
        const { x: x2, y: y2 } = share2;
        
        if (x1 === x2) {
            throw new Error('Cannot recover secret from same x values');
        }
        
        // Solve: y1 = a1 * x1 + a0, y2 = a1 * x2 + a0
        // Therefore: a0 = (y1 * x2 - y2 * x1) / (x2 - x1)
        
        const F = this.poseidon.F;
        const numerator = F.sub(F.mul(y1, x2), F.mul(y2, x1));
        const denominator = F.sub(x2, x1);
        const secret = F.div(numerator, denominator);
        
        return F.toObject(secret).toString();
    }
    
    // Get tree root
    getRoot() {
        return this.tree ? this.tree.getRoot().toString() : null;
    }
    
    // Get identity count
    getIdentityCount() {
        return this.identities.length;
    }
}

module.exports = {
    RLN,
    RLNIdentity,
    RLNProof,
    MerkleTree
};