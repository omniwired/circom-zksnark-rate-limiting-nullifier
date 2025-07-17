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
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        
        uint256 currentEpoch = getCurrentEpoch();
        
        // Check rate limit for this epoch
        if (epochMessages[currentEpoch].length >= getMessageLimit()) {
            revert MessageLimitExceeded();
        }
        
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
        // In a real implementation, you'd need to verify:
        // Hash(recoveredSecret) == identityCommitment
        
        Identity storage identity = identities[identityCommitment];
        if (identity.slashed) revert IdentityAlreadySlashed();
        
        // Slash the identity
        identity.slashed = true;
        
        // Send deposit to slasher as reward
        payable(msg.sender).transfer(identity.deposit);
        
        emit IdentitySlashed(identityCommitment, recoveredSecret);
    }
    
    function recoverSecret(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal pure returns (uint256) {
        // Solve the system of equations:
        // y1 = a1 * x1 + a0
        // y2 = a1 * x2 + a0
        // Therefore: a0 = (y1 * x2 - y2 * x1) / (x2 - x1)
        
        require(x1 != x2, "Cannot recover secret from same x values");
        
        // This is a simplified version - in practice you'd need to handle
        // modular arithmetic properly for the field
        uint256 numerator = (y1 * x2) - (y2 * x1);
        uint256 denominator = x2 - x1;
        
        // In a real implementation, you'd need modular inverse
        return numerator / denominator;
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
        return 1; // One message per epoch per identity
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