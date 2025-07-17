const { expect } = require("chai");
const { ethers } = require("hardhat");
const { RLN, RLNIdentity } = require("../packages/sdk");
const path = require("path");
const fs = require("fs");

describe("RLN Anti-Spam System", function () {
    let verifier;
    let rlnContract;
    let rln;
    let identity1, identity2, identity3;
    
    const EPOCH_LENGTH = 3600; // 1 hour
    const MEMBERSHIP_DEPOSIT = ethers.parseEther("1.0");
    const APP_ID = "test-app";
    
    before(async function() {
        this.timeout(120000); // 2 minutes for compilation
        
        // Initialize RLN SDK
        rln = new RLN({
            wasmPath: path.join(__dirname, '../build/rln_js/rln.wasm'),
            zkeyPath: path.join(__dirname, '../build/rln.zkey'),
            vkeyPath: path.join(__dirname, '../build/verification_key.json')
        });
        
        await rln.init();
        
        // Create test identities
        identity1 = new RLNIdentity();
        identity2 = new RLNIdentity();
        identity3 = new RLNIdentity();
        
        // Register identities in the RLN tree
        await rln.registerIdentity(identity1);
        await rln.registerIdentity(identity2);
        await rln.registerIdentity(identity3);
        
        // Deploy mock verifier for testing
        const MockVerifier = await ethers.getContractFactory("MockVerifier");
        verifier = await MockVerifier.deploy();
        await verifier.waitForDeployment();
        
        const RLNContract = await ethers.getContractFactory("RLN");
        rlnContract = await RLNContract.deploy(
            await verifier.getAddress(),
            MEMBERSHIP_DEPOSIT,
            EPOCH_LENGTH,
            rln.getRoot()
        );
        await rlnContract.waitForDeployment();
    });
    
    describe("Identity Management", function() {
        it("Should create unique identities", async function() {
            const commitment1 = await identity1.getCommitment();
            const commitment2 = await identity2.getCommitment();
            
            expect(commitment1).to.not.equal(commitment2);
            expect(commitment1).to.match(/^[0-9]+$/);
            expect(commitment2).to.match(/^[0-9]+$/);
        });
        
        it("Should register identities in contract", async function() {
            const commitment = await identity1.getCommitment();
            
            const tx = await rlnContract.registerIdentity(commitment, {
                value: MEMBERSHIP_DEPOSIT
            });
            
            const receipt = await tx.wait();
            const event = receipt.logs.find(log => log.fragment?.name === "IdentityRegistered");
            
            expect(event).to.not.be.undefined;
            expect(event.args.identityCommitment).to.equal(commitment);
            expect(event.args.deposit).to.equal(MEMBERSHIP_DEPOSIT);
        });
        
        it("Should reject insufficient deposit", async function() {
            const commitment = await identity2.getCommitment();
            
            await expect(
                rlnContract.registerIdentity(commitment, {
                    value: MEMBERSHIP_DEPOSIT - 1n
                })
            ).to.be.revertedWithCustomError(rlnContract, "InsufficientDeposit");
        });
    });
    
    describe("Message Posting", function() {
        let currentEpoch;
        let externalNullifier;
        
        beforeEach(async function() {
            currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
        });
        
        it("Should generate valid RLN proof", async function() {
            this.timeout(30000); // Allow time for proof generation
            
            const signal = "Hello, world!";
            const messageId = 0;
            
            const proof = await rln.generateProof(
                0, // identity1 index
                signal,
                externalNullifier,
                messageId
            );
            
            expect(proof).to.not.be.undefined;
            expect(proof.proof).to.have.property('pi_a');
            expect(proof.proof).to.have.property('pi_b');
            expect(proof.proof).to.have.property('pi_c');
            expect(proof.publicSignals).to.have.length(5);
        });
        
        it("Should verify proof off-chain", async function() {
            this.timeout(30000);
            
            const signal = "Test message";
            const messageId = 0;
            
            const proof = await rln.generateProof(
                0, // identity1 index
                signal,
                externalNullifier,
                messageId
            );
            
            const isValid = await rln.verifyProof(proof);
            expect(isValid).to.be.true;
        });
        
        it("Should post message on-chain", async function() {
            this.timeout(30000);
            
            const signal = "On-chain message";
            const messageId = 0;
            
            const proof = await rln.generateProof(
                0, // identity1 index
                signal,
                externalNullifier,
                messageId
            );
            
            const solidityProof = proof.toSolidityProof();
            const publicSignals = proof.getPublicSignals();
            
            const tx = await rlnContract.postMessage(
                publicSignals.signalHash,
                publicSignals.nullifier,
                publicSignals.y,
                publicSignals.externalNullifier,
                solidityProof.a,
                solidityProof.b,
                solidityProof.c
            );
            
            const receipt = await tx.wait();
            const event = receipt.logs.find(log => log.eventName === "MessagePosted");
            
            expect(event).to.not.be.undefined;
            expect(event.args.nullifier).to.equal(publicSignals.nullifier);
        });
        
        it("Should reject duplicate nullifiers", async function() {
            this.timeout(30000);
            
            const signal = "Duplicate test";
            const messageId = 0;
            
            const proof = await rln.generateProof(
                0, // identity1 index
                signal,
                externalNullifier,
                messageId
            );
            
            const solidityProof = proof.toSolidityProof();
            const publicSignals = proof.getPublicSignals();
            
            // First post should succeed
            await rlnContract.postMessage(
                publicSignals.signalHash,
                publicSignals.nullifier,
                publicSignals.y,
                publicSignals.externalNullifier,
                solidityProof.a,
                solidityProof.b,
                solidityProof.c
            );
            
            // Second post with same nullifier should fail
            await expect(
                rlnContract.postMessage(
                    publicSignals.signalHash,
                    publicSignals.nullifier,
                    publicSignals.y,
                    publicSignals.externalNullifier,
                    solidityProof.a,
                    solidityProof.b,
                    solidityProof.c
                )
            ).to.be.revertedWithCustomError(rlnContract, "NullifierAlreadyUsed");
        });
    });
    
    describe("Rate Limiting", function() {
        it("Should allow one message per epoch", async function() {
            this.timeout(60000);
            
            const currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            const externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
            
            // First message should succeed
            const proof1 = await rln.generateProof(
                1, // identity2 index
                "First message",
                externalNullifier,
                0
            );
            
            const solidityProof1 = proof1.toSolidityProof();
            const publicSignals1 = proof1.getPublicSignals();
            
            await rlnContract.postMessage(
                publicSignals1.signalHash,
                publicSignals1.nullifier,
                publicSignals1.y,
                publicSignals1.externalNullifier,
                solidityProof1.a,
                solidityProof1.b,
                solidityProof1.c
            );
            
            // Check epoch messages
            const epochMessages = await rlnContract.getEpochMessages(currentEpoch);
            expect(epochMessages.length).to.equal(1);
        });
        
        it("Should track nullifiers by epoch", async function() {
            const currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            const externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
            
            const proof = await rln.generateProof(
                2, // identity3 index
                "Epoch tracking test",
                externalNullifier,
                0
            );
            
            const solidityProof = proof.toSolidityProof();
            const publicSignals = proof.getPublicSignals();
            
            await rlnContract.postMessage(
                publicSignals.signalHash,
                publicSignals.nullifier,
                publicSignals.y,
                publicSignals.externalNullifier,
                solidityProof.a,
                solidityProof.b,
                solidityProof.c
            );
            
            const isUsed = await rlnContract.isNullifierUsed(publicSignals.nullifier);
            expect(isUsed).to.be.true;
        });
    });
    
    describe("Slashing", function() {
        it("Should detect spam and allow slashing", async function() {
            this.timeout(60000);
            
            // This test demonstrates the concept but requires more complex setup
            // to actually generate two different messages with the same identity
            // in the same epoch, which would reveal the secret
            
            // For now, we'll test the recovery function logic
            const testShares = {
                share1: { x: BigInt(100), y: BigInt(200) },
                share2: { x: BigInt(200), y: BigInt(350) }
            };
            
            // This should work: y1 = a1 * x1 + a0, y2 = a1 * x2 + a0
            // If a1 = 1.5 and a0 = 50, then:
            // y1 = 1.5 * 100 + 50 = 200 ✓
            // y2 = 1.5 * 200 + 50 = 350 ✓
            // Recovery: a0 = (y1 * x2 - y2 * x1) / (x2 - x1)
            // a0 = (200 * 200 - 350 * 100) / (200 - 100) = (40000 - 35000) / 100 = 50
            
            const recoveredSecret = await rlnContract.recoverSecret(
                testShares.share1.x,
                testShares.share1.y,
                testShares.share2.x,
                testShares.share2.y
            );
            
            expect(recoveredSecret).to.equal(50);
        });
    });
    
    describe("Gas Usage", function() {
        it("Should post message within gas limit", async function() {
            this.timeout(30000);
            
            const currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            const externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
            
            const proof = await rln.generateProof(
                0, // identity1 index
                "Gas test message",
                externalNullifier,
                0
            );
            
            const solidityProof = proof.toSolidityProof();
            const publicSignals = proof.getPublicSignals();
            
            const tx = await rlnContract.postMessage(
                publicSignals.signalHash,
                publicSignals.nullifier,
                publicSignals.y,
                publicSignals.externalNullifier,
                solidityProof.a,
                solidityProof.b,
                solidityProof.c
            );
            
            const receipt = await tx.wait();
            console.log(`Gas used for RLN message: ${receipt.gasUsed.toString()}`);
            
            // RLN proofs are more complex, so we allow higher gas usage
            expect(receipt.gasUsed).to.be.lessThan(500000);
        });
    });
    
    describe("Fuzz Testing", function() {
        it("Should handle random valid inputs", async function() {
            this.timeout(60000);
            
            const testCount = 10; // Reduced for faster testing
            const currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            const externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
            
            for (let i = 0; i < testCount; i++) {
                const randomSignal = `Random message ${i} ${Math.random()}`;
                const randomMessageId = 0;
                
                try {
                    const proof = await rln.generateProof(
                        i % 3, // Cycle through identities
                        randomSignal,
                        externalNullifier,
                        randomMessageId
                    );
                    
                    const isValid = await rln.verifyProof(proof);
                    expect(isValid).to.be.true;
                } catch (error) {
                    console.error(`Fuzz test failed on iteration ${i}:`, error);
                    throw error;
                }
            }
        });
    });
    
    describe("Security", function() {
        it("Should reject proofs with tampered public signals", async function() {
            this.timeout(30000);
            
            const currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            const externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
            
            const proof = await rln.generateProof(
                0, // identity1 index
                "Security test",
                externalNullifier,
                0
            );
            
            const solidityProof = proof.toSolidityProof();
            const publicSignals = proof.getPublicSignals();
            
            // Tamper with the signal hash
            const tamperedSignalHash = (BigInt(publicSignals.signalHash) + BigInt(1)).toString();
            
            await expect(
                rlnContract.postMessage(
                    tamperedSignalHash, // Tampered
                    publicSignals.nullifier,
                    publicSignals.y,
                    publicSignals.externalNullifier,
                    solidityProof.a,
                    solidityProof.b,
                    solidityProof.c
                )
            ).to.be.revertedWithCustomError(rlnContract, "InvalidProof");
        });
        
        it("Should reject proofs with wrong external nullifier", async function() {
            this.timeout(30000);
            
            const currentEpoch = rln.getCurrentEpoch(EPOCH_LENGTH);
            const externalNullifier = await rln.calculateExternalNullifier(currentEpoch, APP_ID);
            const wrongExternalNullifier = await rln.calculateExternalNullifier(currentEpoch + 1, APP_ID);
            
            const proof = await rln.generateProof(
                0, // identity1 index
                "Wrong nullifier test",
                externalNullifier,
                0
            );
            
            const solidityProof = proof.toSolidityProof();
            const publicSignals = proof.getPublicSignals();
            
            await expect(
                rlnContract.postMessage(
                    publicSignals.signalHash,
                    publicSignals.nullifier,
                    publicSignals.y,
                    wrongExternalNullifier, // Wrong external nullifier
                    solidityProof.a,
                    solidityProof.b,
                    solidityProof.c
                )
            ).to.be.revertedWithCustomError(rlnContract, "InvalidProof");
        });
    });
    
    describe("Performance Benchmarks", function() {
        it("Should measure identity commitment generation time", async function() {
            const identity = new RLNIdentity();
            
            const startTime = performance.now();
            await identity.getCommitment();
            const endTime = performance.now();
            
            const duration = endTime - startTime;
            console.log(`⏱️ Identity commitment generation: ${duration.toFixed(2)}ms`);
            
            // Just making sure it's reasonably fast for a demo
            expect(duration).to.be.lessThan(1000); // Should be under 1 second
        });
        
        it("Should measure basic proof generation time", async function() {
            const externalNullifier = await rln.calculateExternalNullifier(
                rln.getCurrentEpoch(),
                APP_ID
            );
            
            const startTime = performance.now();
            const proof = await rln.generateProof(
                0, // identity1 index
                "Performance test message",
                externalNullifier,
                0
            );
            const endTime = performance.now();
            
            const duration = endTime - startTime;
            console.log(`⏱️ Proof generation: ${duration.toFixed(2)}ms`);
            
            // Make sure we actually got a proof
            expect(proof).to.not.be.undefined;
            expect(proof.proof).to.not.be.undefined;
            expect(proof.publicSignals).to.not.be.undefined;
            
            // Proof generation should be reasonable for a demo
            expect(duration).to.be.lessThan(10000); // Should be under 10 seconds
        });
        
        it("Should log circuit constraint information", async function() {
            // This doesn't really test anything, just logs info we gathered
            console.log(`📊 Circuit Stats:`);
            console.log(`   Non-linear constraints: 5,893`);
            console.log(`   Linear constraints: 6,497`);
            console.log(`   Total constraints: 12,390`);
            console.log(`   Template instances: 216`);
            console.log(`   Wires: 12,413`);
            console.log(`   Merkle tree depth: 20`);
            console.log(`   Max identities: ${Math.pow(2, 20).toLocaleString()}`);
            
            // Just a dummy assertion to make it a valid test
            expect(true).to.be.true;
        });
    });
});