# RLN Anti-Spam Library

A Rate-Limited Nullifier (RLN) implementation using Circom 2 and Groth16 zkSNARKs for spam prevention in anonymous environments with cryptoeconomic incentives.

> **Portfolio Project Status**: This is a demonstration project showcasing RLN implementation fundamentals. The circuit compiles successfully and core functionality is working, with some test implementations incomplete by design.

## Overview

This project demonstrates Circom expertise through an RLN (Rate-Limited Nullifier) system that enables:

- **Anonymous Rate Limiting**: Users can post messages anonymously but are limited to one message per epoch
- **Spam Detection**: Publishing multiple messages in the same epoch reveals the user's secret key
- **Cryptoeconomic Security**: Users stake deposits that can be slashed if they spam
- **Zero-Knowledge Proofs**: Membership and rate limiting are enforced without revealing user identity

## What is RLN?

RLN (Rate-Limited Nullifier) is a zero-knowledge gadget that enables spam prevention in anonymous environments. The key insight is that users can prove they are rate-limited without revealing their identity, and violating the rate limit cryptographically reveals their secret key, enabling economic punishment.

### Core Mechanism

1. **Identity**: Each user has a secret key `a0` and derives an identity commitment `Hash(a0)`
2. **Linear Polynomial**: For each epoch, user knows a line `y = a1 * x + a0` where `a1 = Hash(a0, epoch)`
3. **Shares**: Each message includes a point `(x, y)` on this line where `x = Hash(message)`
4. **Secret Recovery**: Two points reveal the line equation, exposing `a0` and enabling slashing

## Architecture

### Circuit Design (`circuits/rln.circom`)

The RLN circuit enforces:

1. **Merkle Tree Membership**: User's identity commitment exists in the registry
2. **Nullifier Generation**: `nullifier = Hash(a1, messageId)` prevents double-spending
3. **Share Computation**: `y = a1 * x + a0` where `x = Hash(signal)` and `a1 = Hash(a0, epoch)`
4. **Rate Limiting**: Each epoch allows only one message per identity

### Smart Contract (`contracts/RLN.sol`)

The contract provides:

- **Identity Registration**: Stake deposits to join the system
- **Message Posting**: Submit messages with ZK proofs
- **Spam Detection**: Identify duplicate nullifiers in the same epoch
- **Slashing**: Recover secrets and slash spammers' deposits

### JavaScript SDK (`packages/sdk/`)

The SDK offers:

- **Identity Management**: Create and manage RLN identities
- **Proof Generation**: Generate ZK proofs for message posting
- **Merkle Tree Operations**: Maintain identity registry
- **Browser Compatibility**: WASM-based proof generation

## Prerequisites

### Install Circom
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh

# Install Circom directly via cargo
cargo install --git https://github.com/iden3/circom.git
```

### Install Dependencies
```bash
npm install
```

## Usage

### 1. Compile the Circuit
```bash
npm run compile
```

This will:
- Compile the RLN circuit (✅ **Working**)
- Generate trusted setup parameters (⚠️ **Uses dummy file for portfolio demo**)
- Create WASM files for the browser (✅ **Working**)
- Export Solidity verifier contract (⚠️ **Skipped due to dummy setup**)

### 2. Run Tests
```bash
npm test
```

**Current Test Status**: 16/27 tests passing (59% pass rate)

Tests verify:
- ✅ **Identity registration and commitment generation** - Working
- ✅ **Circuit compilation and constraint validation** - Working  
- ✅ **Cryptographic primitives (Poseidon, SSS)** - Working
- ⚠️ **Message posting with rate limiting** - Partially implemented
- ⚠️ **Spam detection and slashing mechanisms** - Contract methods incomplete
- ⚠️ **Proof generation and verification** - Core working, edge cases need handling
- ✅ **Gas usage optimization** - Basic benchmarks working

### 3. Demo CLI
```bash
# Basic demo (note: CLI implementation is incomplete)
npm run demo
```

> **Note**: CLI demo is a placeholder. The core functionality is demonstrated through the test suite.

### 4. Deploy Contracts
```bash
npm run deploy
```

> **Note**: Deployment script exists but may need adjustment for production use.

## Project Structure

```
rln-anti-spam/
├── circuits/
│   └── rln.circom              # Main RLN circuit
├── contracts/
│   ├── RLN.sol                 # Main RLN contract
│   └── RLNVerifier.sol         # Auto-generated verifier
├── packages/
│   └── sdk/
│       ├── index.js            # JavaScript SDK
│       └── wasm/               # WASM files for browser
├── test/
│   └── rln.spec.js             # Comprehensive tests
├── cli/
│   └── demo.js                 # CLI demonstration tool
├── scripts/
│   └── compile.js              # Circuit compilation script
└── build/                      # Compilation artifacts
```

## Key Features

### Rate Limiting
- One message per epoch per identity
- Configurable epoch length (default: 1 hour)
- Cryptographic enforcement via nullifiers

### Spam Detection
- Duplicate nullifiers in the same epoch indicate spam
- Automatic secret key recovery from multiple shares
- Slashing mechanism with economic incentives

### Privacy
- Anonymous message posting
- Zero-knowledge membership proofs
- Identity commitments hide actual secrets

### Security
- Groth16 proofs for efficiency and security
- Merkle tree membership verification
- Cryptoeconomic slashing deterrent

## Circuit Parameters

**Actual Compiled Circuit Stats:**
- **Merkle Tree Height**: 20 levels (supports 2^20 identities)
- **Message Limit**: 1 per epoch per identity  
- **Template Instances**: 216
- **Non-linear Constraints**: 5,893
- **Linear Constraints**: 6,497
- **Total Constraints**: 12,390
- **Public Inputs**: 2 (x, externalNullifier)
- **Private Inputs**: 43 (identitySecret, pathElements, pathIndices, messageId)
- **Public Outputs**: 3 (y, nullifier, root)
- **Wires**: 12,413

## Gas Benchmarks

**Actual Test Results:**
| Operation | Gas Usage |
|-----------|-----------|
| MockVerifier Deployment | 171,117 gas |
| RLN Contract Deployment | 929,760 gas |
| Identity Registration | 95,339 gas |
| Message Posting | *Not yet implemented* |
| Spam Detection | *Not yet implemented* |
| Slashing | *Not yet implemented* |

## SDK Bundle Size

- **Compressed**: < 1.2 MB gzipped
- **Includes**: WASM circuit, snarkjs, utilities
- **Browser Compatible**: Works in modern browsers
- **WebWorker Support**: Non-blocking proof generation

## Security Considerations

1. **Trusted Setup**: Powers of Tau ceremony should involve multiple contributors
2. **Deposit Security**: Stake amounts should exceed spam profit incentives
3. **Epoch Management**: Epoch length affects both UX and security
4. **Secret Storage**: Users must securely store their identity secrets
5. **Merkle Tree Updates**: Registry updates should be carefully managed

## Mathematical Foundation

The RLN system is based on Shamir's Secret Sharing:

```
Given a linear polynomial: y = a1 * x + a0
- a0 is the secret key
- a1 = Hash(a0, epoch) ensures epoch-specific shares
- x = Hash(message) ensures message-specific shares
- y is the public share value

Two shares (x1, y1) and (x2, y2) reveal:
a0 = (y1 * x2 - y2 * x1) / (x2 - x1)
```

This mathematical property enables automatic secret recovery when users violate rate limits.

## Recent Fixes & Status

### ✅ Issues Resolved

1. **Circuit Compilation Fixed**
   - Updated all templates to use proper Circom 2.x syntax
   - Fixed component instantiation patterns
   - Resolved invalid template syntax errors

2. **SDK Improvements**
   - Fixed MerkleTree empty tree handling
   - Added proper string-to-BigInt conversion for signals
   - Updated external nullifier calculation for string inputs

3. **Contract & Test Updates**
   - Added MockVerifier for testing
   - Updated ethers.js v6 compatibility
   - Fixed deployment and event handling

4. **Dependencies**
   - Rust toolchain updated to 1.88.0
   - Circom 2.2.2 installed and working
   - All npm dependencies resolved

### ⚠️ Known Limitations

This is a portfolio demonstration project with some intentional limitations:

- **Powers of Tau**: Uses dummy file instead of real trusted setup
- **Verifier Contract**: Mock implementation for testing only
- **Contract Methods**: Some slashing/recovery methods incomplete
- **CLI Demo**: Placeholder implementation
- **Edge Cases**: Some test scenarios need additional handling

### 📊 Current Metrics

- **Circuit Compilation**: ✅ Successful
- **Test Suite**: 16/27 tests passing (59%)
- **Gas Efficiency**: Basic benchmarks working
- **SDK Functionality**: Core features operational

## 📊 Performance & Benchmarks

### Current Performance (What I've Measured So Far)

**Circuit Compilation Times:**
- Circuit compilation: ~2-3 seconds (on M1 Mac)
- Constraint generation: 12,390 total constraints
- WASM generation: ~1 second

**Test Performance:**
- Identity commitment generation: ~10ms
- Basic proof generation: Haven't timed this yet (TODO!)
- Merkle tree operations: Pretty fast, but should measure properly

**Gas Usage (From Test Results):**
- Contract deployment: 929,760 gas (seems high?)
- Identity registration: 95,339 gas (reasonable)
- Message posting: Not implemented yet

### Performance Ideas for Later

Things I want to measure when I have more time:
- [ ] Proof generation time across different message sizes
- [ ] Memory usage during proof generation
- [ ] Constraint count optimization opportunities
- [ ] Browser vs Node.js performance differences
- [ ] Batch proof generation efficiency

> **Note**: These are just rough measurements from my development machine. Real benchmarking would need proper testing infrastructure!

## 🔒 Security Analysis

### What I Think I Got Right

**Cryptographic Foundations:**
- Using Poseidon hash (designed for zk-SNARKs)
- Proper Shamir's Secret Sharing implementation
- Merkle tree membership proofs
- Nullifier uniqueness enforcement

**Circuit Security:**
- Input validation for path indices (must be 0 or 1)
- Range checking for message limits
- Proper component instantiation (finally!)

### Known Security Limitations

**⚠️ Things I'm Worried About:**
- **Trusted Setup**: Using dummy Powers of Tau file (big red flag!)
- **Mock Verifier**: Always returns true (obviously insecure)
- **No Input Validation**: Contract doesn't validate proof inputs thoroughly
- **Secret Storage**: No guidance on secure key management
- **Replay Protection**: Basic nullifier checking but needs more testing

**🤔 Things I'm Not Sure About:**
- Are my constraint counts reasonable for this circuit size?
- Is the merkle tree depth (20) secure enough?
- Should I be using different hash functions for different purposes?
- Are there timing attacks I should worry about?

**📚 What I Want to Learn More About:**
- How to properly validate elliptic curve points
- Best practices for zkSNARK circuit security
- Common attack vectors against RLN systems
- Proper trusted setup procedures

> **Disclaimer**: This is a learning project! Don't use this in production without proper security audits and fixes.

## 🚀 Future Improvements

### Short-term Goals (If I Had More Time)

**Better Testing:**
- [ ] Add performance benchmarking tests
- [ ] Test edge cases and error conditions
- [ ] Add fuzzing tests with random inputs
- [ ] Measure constraint count scaling

**Documentation:**
- [ ] Add more code comments explaining the math
- [ ] Create simple diagrams showing the RLN flow
- [ ] Write a tutorial for beginners like me
- [ ] Document all the gotchas I encountered

**Development Experience:**
- [ ] Add pre-commit hooks for linting
- [ ] Automate circuit compilation in CI
- [ ] Add better error messages
- [ ] Create development scripts for common tasks

### Medium-term Ideas (Dream Features)

**Circuit Optimizations:**
- [ ] Reduce constraint count where possible
- [ ] Add support for different tree depths
- [ ] Implement batch verification
- [ ] Optimize Poseidon usage

**Production Readiness:**
- [ ] Proper trusted setup integration
- [ ] Real verifier contract generation
- [ ] Comprehensive input validation
- [ ] Rate limiting per user/epoch tracking

**Developer Experience:**
- [ ] Browser-based demo interface
- [ ] Interactive circuit debugger
- [ ] Performance profiling tools
- [ ] Better error handling and logging

### Long-term Vision (Maybe Someday)

**Advanced Features:**
- [ ] Support for different proving systems (PLONK?)
- [ ] Integration with existing identity systems
- [ ] Decentralized trusted setup coordination
- [ ] Cross-chain compatibility

**Research Directions:**
- [ ] Explore different rate limiting strategies
- [ ] Investigate privacy-preserving optimizations
- [ ] Study scaling solutions for large user bases
- [ ] Research post-quantum security implications

> **Reality Check**: This is a portfolio project, so most of these are just ideas to show I'm thinking about the bigger picture!

## Development

### Linting
```bash
npm run lint
```

### Type Checking
```bash
npm run typecheck
```

### Building SDK
```bash
npm run build:sdk
```

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## References

- [RLN Paper](https://rate-limiting-nullifier.github.io/rln-docs/)
- [Circom Documentation](https://docs.circom.io/)
- [snarkjs Library](https://github.com/iden3/snarkjs)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)