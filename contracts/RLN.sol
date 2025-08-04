// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IVerifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory input
    ) external view returns (bool);
}

// Mock verifier for testing
contract MockVerifier is IVerifier {
    function verifyProof(
        uint[2] memory,
        uint[2][2] memory,
        uint[2] memory,
        uint[5] memory
    ) external pure override returns (bool) {
        return true; // Always return true for testing
    }
}

contract RLN {
    IVerifier public immutable verifier;
    
    struct Identity {
        uint256 commitment;
        uint256 deposit;
        bool slashed;
    }
    
    struct Message {
        uint256 signalHash;
        uint256 nullifier;
        uint256 y;
        uint256 timestamp;
        address sender;
    }
    
    // Storage
    mapping(uint256 => Identity) public identities;
    mapping(uint256 => Message) public messages;
    mapping(uint256 => uint256[]) public epochMessages; // epoch -> message nullifiers
    mapping(uint256 => bool) public usedNullifiers;
    mapping(uint256 => uint256) public nullifierToEpoch;
    
    uint256 public immutable membershipDeposit;
    uint256 public immutable epochLength;
    uint256 public identityCount;
    uint256 public messageCount;
    uint256 public merkleRoot;
    
    event IdentityRegistered(uint256 indexed identityCommitment, uint256 deposit);
    event MessagePosted(uint256 indexed messageId, uint256 nullifier, uint256 epoch);
    event IdentitySlashed(uint256 indexed identityCommitment, uint256 recoveredSecret);
    event RootUpdated(uint256 newRoot);
    
    error InsufficientDeposit();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error IdentityAlreadySlashed();
    error MessageLimitExceeded();
    error InvalidEpoch();
    error NoSlashableOffense();
    
    modifier onlyValidEpoch(uint256 epoch) {
        if (epoch != getCurrentEpoch()) revert InvalidEpoch();
        _;
    }
    
    constructor(
        address _verifier,
        uint256 _membershipDeposit,
        uint256 _epochLength,
        uint256 _initialRoot
    ) {
        verifier = IVerifier(_verifier);
        membershipDeposit = _membershipDeposit;
        epochLength = _epochLength;
        merkleRoot = _initialRoot;
    }
    
    function registerIdentity(uint256 identityCommitment) external payable {
        require(identityCommitment < FIELD_MODULUS, "Invalid identity commitment");
        require(identities[identityCommitment].commitment == 0, "Identity already registered");
        if (msg.value < membershipDeposit) revert InsufficientDeposit();
        
        identities[identityCommitment] = Identity({
            commitment: identityCommitment,
            deposit: msg.value,
            slashed: false
        });
        
        identityCount++;
        emit IdentityRegistered(identityCommitment, msg.value);
        
        // In a real implementation, this would update the merkle tree
        // For this demo, we'll emit an event
        emit RootUpdated(merkleRoot);
    }
    
    function postMessage(
        uint256 signalHash,
        uint256 nullifier,
        uint256 y,
        uint256 externalNullifier,
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c
    ) external {
        // Input validation
        require(signalHash < FIELD_MODULUS, "Invalid signal hash");
        require(nullifier < FIELD_MODULUS, "Invalid nullifier");
        require(y < FIELD_MODULUS, "Invalid y coordinate");
        require(externalNullifier < FIELD_MODULUS, "Invalid external nullifier");
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        
        // Extract epoch from external nullifier (should be Hash(epoch, appId))
        // In a real implementation, we'd need a way to extract/verify the epoch
        // For this demo, we'll use block timestamp as epoch
        uint256 currentEpoch = getCurrentEpoch();
        
        // In RLN, rate limiting is enforced cryptographically via nullifiers
        // The circuit ensures only one message per identity per epoch
        // Contract just needs to prevent nullifier reuse
        
        // Verify the ZK proof
        uint[5] memory input = [
            externalNullifier,
            y,
            nullifier,
            merkleRoot,
            signalHash
        ];
        
        if (!verifier.verifyProof(a, b, c, input)) revert InvalidProof();
        
        // Store the message
        uint256 messageId = messageCount++;
        messages[messageId] = Message({
            signalHash: signalHash,
            nullifier: nullifier,
            y: y,
            timestamp: block.timestamp,
            sender: msg.sender
        });
        
        // Track nullifier usage
        usedNullifiers[nullifier] = true;
        nullifierToEpoch[nullifier] = currentEpoch;
        epochMessages[currentEpoch].push(nullifier);
        
        emit MessagePosted(messageId, nullifier, currentEpoch);
    }
    
    function slash(
        uint256 nullifier1,
        uint256 nullifier2,
        uint256 identityCommitment
    ) external {
        require(nullifier1 != nullifier2, "Cannot slash with same nullifier");
        require(nullifier1 < FIELD_MODULUS && nullifier2 < FIELD_MODULUS, "Invalid nullifiers");
        require(identityCommitment < FIELD_MODULUS, "Invalid identity commitment");
        require(usedNullifiers[nullifier1] && usedNullifiers[nullifier2], "Nullifiers not used");
        // Verify both nullifiers are from the same epoch
        uint256 epoch1 = nullifierToEpoch[nullifier1];
        uint256 epoch2 = nullifierToEpoch[nullifier2];
        
        if (epoch1 != epoch2 || epoch1 == 0) revert NoSlashableOffense();
        
        // Get the messages
        uint256 messageId1 = findMessageByNullifier(nullifier1);
        uint256 messageId2 = findMessageByNullifier(nullifier2);
        
        Message storage msg1 = messages[messageId1];
        Message storage msg2 = messages[messageId2];
        
        // Verify the messages are different
        if (msg1.signalHash == msg2.signalHash) revert NoSlashableOffense();
        
        // Recover the secret key using the two shares
        uint256 recoveredSecret = recoverSecret(
            msg1.signalHash,
            msg1.y,
            msg2.signalHash,
            msg2.y
        );
        
        // Verify the recovered secret matches the identity commitment
        uint256 computedCommitment = uint256(keccak256(abi.encodePacked(recoveredSecret))) % FIELD_MODULUS;
        if (computedCommitment != identityCommitment) revert NoSlashableOffense();
        
        Identity storage identity = identities[identityCommitment];
        if (identity.commitment == 0) revert NoSlashableOffense(); // Identity doesn't exist
        if (identity.slashed) revert IdentityAlreadySlashed();
        
        // Slash the identity
        identity.slashed = true;
        
        // Send deposit to slasher as reward
        payable(msg.sender).transfer(identity.deposit);
        
        emit IdentitySlashed(identityCommitment, recoveredSecret);
    }
    
    // BN254 field modulus
    uint256 private constant FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    function recoverSecret(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) public pure returns (uint256) {
        // Solve the system of equations:
        // y1 = a1 * x1 + a0 (mod p)
        // y2 = a1 * x2 + a0 (mod p)
        // Therefore: a0 = (y1 * x2 - y2 * x1) * (x2 - x1)^(-1) (mod p)
        
        require(x1 != x2, "Cannot recover secret from same x values");
        require(x1 < FIELD_MODULUS && x2 < FIELD_MODULUS, "Invalid field elements");
        require(y1 < FIELD_MODULUS && y2 < FIELD_MODULUS, "Invalid field elements");
        
        // Calculate numerator: (y1 * x2 - y2 * x1) mod p
        uint256 term1 = mulmod(y1, x2, FIELD_MODULUS);
        uint256 term2 = mulmod(y2, x1, FIELD_MODULUS);
        uint256 numerator = term1 >= term2 ? term1 - term2 : FIELD_MODULUS - (term2 - term1);
        
        // Calculate denominator: (x2 - x1) mod p
        uint256 denominator = x2 >= x1 ? x2 - x1 : FIELD_MODULUS - (x1 - x2);
        
        // Calculate modular inverse and multiply
        uint256 denominatorInv = modInverse(denominator, FIELD_MODULUS);
        return mulmod(numerator, denominatorInv, FIELD_MODULUS);
    }
    
    // Extended Euclidean Algorithm for modular inverse
    function modInverse(uint256 a, uint256 m) internal pure returns (uint256) {
        require(a < m, "Invalid input for modular inverse");
        
        if (a == 0) return 0;
        
        int256 m0 = int256(m);
        int256 x0 = 0;
        int256 x1 = 1;
        int256 a_signed = int256(a);
        
        while (a_signed > 1) {
            int256 q = a_signed / m0;
            int256 t = m0;
            
            m0 = a_signed % m0;
            a_signed = t;
            t = x0;
            
            x0 = x1 - q * x0;
            x1 = t;
        }
        
        if (x1 < 0) x1 += int256(m);
        
        return uint256(x1);
    }
    
    function findMessageByNullifier(uint256 nullifier) internal view returns (uint256) {
        for (uint256 i = 0; i < messageCount; i++) {
            if (messages[i].nullifier == nullifier) {
                return i;
            }
        }
        revert("Message not found");
    }
    
    function getCurrentEpoch() public view returns (uint256) {
        return block.timestamp / epochLength;
    }
    
    function getMessageLimit() public pure returns (uint256) {
        return 100; // Allow multiple messages for testing (should be 1 per identity in production)
    }
    
    function getEpochMessages(uint256 epoch) external view returns (uint256[] memory) {
        return epochMessages[epoch];
    }
    
    function isNullifierUsed(uint256 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }
    
    function updateRoot(uint256 newRoot) external {
        // In a real implementation, this would be restricted to authorized updaters
        // or use an incremental merkle tree
        merkleRoot = newRoot;
        emit RootUpdated(newRoot);
    }
}