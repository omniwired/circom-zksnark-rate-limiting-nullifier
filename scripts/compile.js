const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const circuitName = 'rln';
const buildDir = path.join(__dirname, '../build');
const circuitsDir = path.join(__dirname, '../circuits');
const contractsDir = path.join(__dirname, '../contracts');
const ptauPath = path.join(buildDir, 'powersOfTau.ptau');

async function main() {
    console.log('🔧 Starting RLN circuit compilation process...\n');

    // Create build directory if it doesn't exist
    if (!fs.existsSync(buildDir)) {
        fs.mkdirSync(buildDir, { recursive: true });
    }

    // Step 1: Compile the circuit
    console.log('📝 Step 1: Compiling RLN circuit...');
    try {
        execSync(
            `circom ${path.join(circuitsDir, circuitName)}.circom --r1cs --wasm --sym -o ${buildDir}`,
            { stdio: 'inherit' }
        );
        console.log('✅ RLN circuit compiled successfully!\n');
    } catch (error) {
        console.error('❌ Circuit compilation failed:', error.message);
        process.exit(1);
    }

    // Step 2: Generate Powers of Tau (or use existing)
    console.log('🔑 Step 2: Checking Powers of Tau...');
    if (!fs.existsSync(ptauPath)) {
        console.log('⚠️  Powers of Tau not found. For production, download from:');
        console.log('   https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau');
        console.log('   Skipping proof generation for now...\n');
        
        // Create a dummy file for demonstration
        fs.writeFileSync(ptauPath, 'dummy ptau file - replace with real one');
        return;
    } else {
        console.log('ℹ️  Powers of Tau exists, continuing...\n');
    }

    // Step 3: Setup Phase 2
    console.log('🔐 Step 3: Circuit-specific setup (Phase 2)...');
    const r1csPath = path.join(buildDir, `${circuitName}.r1cs`);
    const zkeyPath = path.join(buildDir, `${circuitName}.zkey`);
    
    try {
        await snarkjs.zKey.newZKey(r1csPath, ptauPath, zkeyPath);
        console.log('✅ Circuit-specific setup completed!\n');
    } catch (error) {
        console.error('❌ Circuit setup failed:', error.message);
        process.exit(1);
    }

    // Step 4: Export verification key
    console.log('📤 Step 4: Exporting verification key...');
    const vkeyPath = path.join(buildDir, 'verification_key.json');
    
    try {
        const vKey = await snarkjs.zKey.exportVerificationKey(zkeyPath);
        fs.writeFileSync(vkeyPath, JSON.stringify(vKey, null, 2));
        console.log('✅ Verification key exported!\n');
    } catch (error) {
        console.error('❌ Verification key export failed:', error.message);
        process.exit(1);
    }

    // Step 5: Generate Solidity verifier
    console.log('📜 Step 5: Generating Solidity verifier contract...');
    
    try {
        const templates = {
            groth16: fs.readFileSync(
                path.join(__dirname, '../node_modules/snarkjs/templates/verifier_groth16.sol.ejs'),
                'utf8'
            )
        };
        
        const verifierCode = await snarkjs.zKey.exportSolidityVerifier(zkeyPath, templates);
        
        // Create contracts directory if it doesn't exist
        if (!fs.existsSync(contractsDir)) {
            fs.mkdirSync(contractsDir, { recursive: true });
        }
        
        fs.writeFileSync(
            path.join(contractsDir, 'RLNVerifier.sol'),
            verifierCode
        );
        console.log('✅ Solidity verifier generated!\n');
    } catch (error) {
        console.error('❌ Solidity verifier generation failed:', error.message);
        process.exit(1);
    }

    // Step 6: Generate WASM for browser use
    console.log('🌐 Step 6: Preparing WASM for browser...');
    const wasmSrcPath = path.join(buildDir, `${circuitName}_js`, `${circuitName}.wasm`);
    const wasmDestPath = path.join(__dirname, '../packages/sdk/wasm', `${circuitName}.wasm`);
    
    try {
        // Create SDK wasm directory
        const wasmDir = path.dirname(wasmDestPath);
        if (!fs.existsSync(wasmDir)) {
            fs.mkdirSync(wasmDir, { recursive: true });
        }
        
        // Copy WASM file
        fs.copyFileSync(wasmSrcPath, wasmDestPath);
        
        // Copy zkey file
        const zkeyDestPath = path.join(wasmDir, `${circuitName}.zkey`);
        fs.copyFileSync(zkeyPath, zkeyDestPath);
        
        console.log('✅ WASM files prepared for SDK!\n');
    } catch (error) {
        console.error('❌ WASM preparation failed:', error.message);
        process.exit(1);
    }

    // Print circuit info
    console.log('📊 RLN Circuit Information:');
    const r1cs = await snarkjs.r1cs.info(r1csPath);
    console.log(`   Total constraints: ${r1cs.nConstraints}`);
    console.log(`   Public inputs: ${r1cs.nPublic}`);
    console.log(`   Private inputs: ${r1cs.nPrvInputs}`);
    console.log(`   Outputs: ${r1cs.nOutputs}`);
    console.log(`   Maximum rate limit: 2^16 = ${2**16} messages per epoch\n`);

    console.log('🎉 RLN compilation process completed successfully!');
    console.log('📁 Build artifacts saved to:', buildDir);
    console.log('🌐 SDK files saved to:', path.join(__dirname, '../packages/sdk/wasm'));
}

main().catch((error) => {
    console.error('Unexpected error:', error);
    process.exit(1);
});