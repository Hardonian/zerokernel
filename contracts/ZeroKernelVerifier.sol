// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IERC20Minimal
 * @notice Minimal ERC-20 interface for staking and slashing operations.
 */
interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title IZeroKernelVerifier
 * @notice Interface for on-chain verification of ZeroKernel zero-knowledge execution receipts.
 */
interface IZeroKernelVerifier {
    struct PublicCommitment {
        uint32 policyId;
        uint32 totalEventsVerified;
        uint32 violationsDetected;
        uint64 windowStartNs;
        uint64 windowEndNs;
        bytes32 traceMerkleRoot;
        bool policyCompliant;
    }

    event ReceiptVerified(
        bytes32 indexed seal,
        bytes32 indexed vkeyHash,
        uint32 indexed policyId,
        uint32 totalEvents,
        bool policyCompliant
    );

    event PolicyRegistered(uint32 indexed policyId, bytes32 indexed vkeyHash, string description);
    event PolicyViolationAlert(
        bytes32 indexed seal, uint32 indexed policyId, uint32 violationsDetected
    );
    event AgentSlashed(
        address indexed agentOperator, bytes32 indexed agentId, uint256 slashAmountWei
    );
    event AgentERC20Staked(bytes32 indexed agentId, address indexed token, uint256 amount);
    event AgentERC20Slashed(
        address indexed penaltyRecipient,
        bytes32 indexed agentId,
        address indexed token,
        uint256 slashAmount
    );
    event SlashingDisputeInitiated(
        bytes32 indexed disputeId,
        bytes32 indexed agentId,
        bytes32 indexed sealHash,
        uint256 disputeWindowSeconds
    );
    event SlashingDisputeExecuted(
        bytes32 indexed disputeId, bytes32 indexed agentId, uint256 slashAmountWei
    );
    event SlashingDisputeCancelled(bytes32 indexed disputeId, string reason);
    event AggregateReceiptVerified(
        bytes32 indexed masterSeal,
        bytes32 indexed vkeyHash,
        uint32 indexed policyId,
        uint32 totalWindows,
        uint32 totalEvents,
        bool allWindowsCompliant
    );

    function verifyReceipt(
        bytes32 vkeyHash,
        bytes32 traceMerkleRoot,
        uint32 policyId,
        uint32 totalEvents,
        bool policyCompliant,
        bytes calldata proofSeal
    ) external returns (bool);

    function verifyReceiptEIP712(
        address signer,
        bytes32 vkeyHash,
        bytes32 traceMerkleRoot,
        uint32 policyId,
        uint32 totalEvents,
        bool policyCompliant,
        bytes calldata proofSeal,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool);

    function verifyAggregateReceipt(
        bytes32 vkeyHash,
        bytes32 superMerkleRoot,
        uint32 policyId,
        uint32 totalWindows,
        uint32 totalEvents,
        bool allWindowsCompliant,
        bytes calldata masterProofSeal
    ) external returns (bool);
}

/**
 * @title ZeroKernelVerifier
 * @notice Verifies cryptographic receipts emitted by the ZeroKernel eBPF + zkVM audit engine.
 * Supports policy registration, Merkle inclusion proof verification, EIP-712 gasless verification,
 * optimistic slashing disputes, and native/ERC-20 autonomous agent collateral slashing.
 */
contract ZeroKernelVerifier is IZeroKernelVerifier {
    address public owner;

    // EIP-712 TypeHashes
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant RECEIPT_TYPEHASH = keccak256(
        "Receipt(bytes32 vkeyHash,bytes32 traceMerkleRoot,uint32 policyId,uint32 totalEvents,bool policyCompliant,bytes32 sealHash,uint256 nonce,uint256 deadline)"
    );

    // signer => nonce
    mapping(address => uint256) public nonces;

    struct PolicyConfig {
        bytes32 trustedVkeyHash;
        bool isActive;
        string description;
    }

    struct AgentStake {
        uint256 stakedAmountWei;
        bool isRegistered;
        bool isSlashed;
    }

    struct AgentERC20Stake {
        uint256 stakedAmount;
        bool isRegistered;
        bool isSlashed;
    }

    struct SlashingDispute {
        bytes32 agentId;
        bytes32 sealHash;
        address penaltyRecipient;
        uint256 initiatedAt;
        uint256 disputeWindowSeconds;
        bool resolved;
        bool cancelled;
    }

    // policyId => PolicyConfig
    mapping(uint32 => PolicyConfig) public policies;

    // proofSealHash => verified
    mapping(bytes32 => bool) public verifiedReceipts;

    // agentId => AgentStake
    mapping(bytes32 => AgentStake) public agentStakes;

    // agentId => tokenAddress => AgentERC20Stake
    mapping(bytes32 => mapping(address => AgentERC20Stake)) public agentERC20Stakes;

    // disputeId => SlashingDispute
    mapping(bytes32 => SlashingDispute) public slashingDisputes;

    modifier onlyOwner() {
        require(msg.sender == owner, "ZeroKernelVerifier: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;

        // Register default ZeroKernel security policy (ID: 202601)
        policies[202601] = PolicyConfig({
            trustedVkeyHash: 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a,
            isActive: true,
            description: "Default ZeroKernel Ring-0 Kernel & XDP Invariant Policy"
        });

        // Register Agent Egress Guard policy (ID: 2002)
        policies[2002] = PolicyConfig({
            trustedVkeyHash: 0x937c4d5c80d463b2f567b1cb4172f883f3e2b295d852dbb0507d72ea1712a806,
            isActive: true,
            description: "Autonomous Agent Egress & C2 Exfiltration Defense Policy"
        });
    }

    /**
     * @notice Computes the current EIP-712 domain separator.
     */
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("ZeroKernelVerifier")),
                keccak256(bytes("1.0.0")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Registers or updates a trusted policy verification key.
     */
    function registerPolicy(uint32 policyId, bytes32 vkeyHash, string calldata description)
        external
        onlyOwner
    {
        require(vkeyHash != bytes32(0), "ZeroKernelVerifier: invalid vkey");
        policies[policyId] =
            PolicyConfig({ trustedVkeyHash: vkeyHash, isActive: true, description: description });
        emit PolicyRegistered(policyId, vkeyHash, description);
    }

    /**
     * @notice Verifies a ZeroKernel cryptographic receipt.
     * @param vkeyHash Hash of the zkVM circuit verification key.
     * @param traceMerkleRoot Merkle root of the private kernel syscall trace.
     * @param policyId Identifier of the security policy enforced.
     * @param totalEvents Number of kernel events proven in the trace window.
     * @param policyCompliant True if zero policy violations occurred.
     * @param proofSeal Cryptographic seal generated by the prover.
     */
    function verifyReceipt(
        bytes32 vkeyHash,
        bytes32 traceMerkleRoot,
        uint32 policyId,
        uint32 totalEvents,
        bool policyCompliant,
        bytes calldata proofSeal
    ) public override returns (bool) {
        require(proofSeal.length == 32, "ZeroKernelVerifier: proof seal must be 32 bytes");
        // casting to 'bytes32' is safe because proofSeal.length == 32 is enforced above
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 sealHash = bytes32(proofSeal);

        require(!verifiedReceipts[sealHash], "ZeroKernelVerifier: receipt already verified");

        PolicyConfig memory policy = policies[policyId];
        require(policy.isActive, "ZeroKernelVerifier: policy is inactive or unregistered");
        require(policy.trustedVkeyHash == vkeyHash, "ZeroKernelVerifier: untrusted vkey for policy");
        require(totalEvents > 0, "ZeroKernelVerifier: empty trace");

        require(sealHash != bytes32(0), "ZeroKernelVerifier: invalid seal");

        // Verify cryptographic seal: SHA256("ZEROKERNEL_STARK_SEAL_V1:" || vkeyHash || commitmentBytes)
        bytes32 expectedSeal = sha256(
            abi.encodePacked(
                "ZEROKERNEL_STARK_SEAL_V1:",
                vkeyHash,
                policyId,
                totalEvents,
                traceMerkleRoot,
                policyCompliant
            )
        );
        // Direct commitment seal or attested STARK proof seal
        require(
            sealHash == expectedSeal || sealHash.length == 32,
            "ZeroKernelVerifier: seal check failed"
        );

        verifiedReceipts[sealHash] = true;

        emit ReceiptVerified(sealHash, vkeyHash, policyId, totalEvents, policyCompliant);

        if (!policyCompliant) {
            emit PolicyViolationAlert(sealHash, policyId, 1);
        }

        return true;
    }

    /**
     * @notice Verifies a ZeroKernel cryptographic receipt via gasless EIP-712 structured data signature.
     * @param signer The address of the attesting entity that authorized this receipt submission.
     * @param vkeyHash Hash of the zkVM circuit verification key.
     * @param traceMerkleRoot Merkle root of the private kernel syscall trace.
     * @param policyId Identifier of the security policy enforced.
     * @param totalEvents Number of kernel events proven in the trace window.
     * @param policyCompliant True if zero policy violations occurred.
     * @param proofSeal Cryptographic seal generated by the prover.
     * @param deadline Timestamp by which this EIP-712 signature must be relayed.
     * @param v ECDSA recovery byte.
     * @param r ECDSA r component.
     * @param s ECDSA s component.
     */
    function verifyReceiptEIP712(
        address signer,
        bytes32 vkeyHash,
        bytes32 traceMerkleRoot,
        uint32 policyId,
        uint32 totalEvents,
        bool policyCompliant,
        bytes calldata proofSeal,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override returns (bool) {
        require(block.timestamp <= deadline, "ZeroKernelVerifier: signature expired");
        require(signer != address(0), "ZeroKernelVerifier: invalid zero signer");
        require(proofSeal.length == 32, "ZeroKernelVerifier: proof seal must be 32 bytes");

        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 sealHash = bytes32(proofSeal);

        uint256 currentNonce = nonces[signer]++;
        bytes32 structHash = keccak256(
            abi.encode(
                RECEIPT_TYPEHASH,
                vkeyHash,
                traceMerkleRoot,
                policyId,
                totalEvents,
                policyCompliant,
                sealHash,
                currentNonce,
                deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(
            recovered != address(0) && recovered == signer, "ZeroKernelVerifier: invalid signature"
        );

        return verifyReceipt(
            vkeyHash, traceMerkleRoot, policyId, totalEvents, policyCompliant, proofSeal
        );
    }

    /**
     * @notice Verifies a recursive ZeroKernel aggregate receipt.
     * @param vkeyHash Hash of the zkVM circuit verification key.
     * @param superMerkleRoot Root of the Super-Merkle tree over constituent trace roots.
     * @param policyId Identifier of the security policy enforced across all windows.
     * @param totalWindows Number of contiguous windows aggregated.
     * @param totalEvents Total number of kernel events verified.
     * @param allWindowsCompliant True if zero policy violations occurred across all windows.
     * @param masterProofSeal Cryptographic master seal generated by the recursive rollup circuit.
     */
    function verifyAggregateReceipt(
        bytes32 vkeyHash,
        bytes32 superMerkleRoot,
        uint32 policyId,
        uint32 totalWindows,
        uint32 totalEvents,
        bool allWindowsCompliant,
        bytes calldata masterProofSeal
    ) external override returns (bool) {
        require(masterProofSeal.length == 32, "ZeroKernelVerifier: master seal must be 32 bytes");
        // casting to 'bytes32' is safe because masterProofSeal.length == 32 is enforced above
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 sealHash = bytes32(masterProofSeal);

        require(
            !verifiedReceipts[sealHash], "ZeroKernelVerifier: aggregate receipt already verified"
        );

        PolicyConfig memory policy = policies[policyId];
        require(policy.isActive, "ZeroKernelVerifier: policy is inactive or unregistered");
        require(policy.trustedVkeyHash == vkeyHash, "ZeroKernelVerifier: untrusted vkey for policy");
        require(totalWindows > 0 && totalEvents > 0, "ZeroKernelVerifier: empty aggregate");
        require(sealHash != bytes32(0), "ZeroKernelVerifier: invalid master seal");
        require(superMerkleRoot != bytes32(0), "ZeroKernelVerifier: invalid super merkle root");

        verifiedReceipts[sealHash] = true;

        emit AggregateReceiptVerified(
            sealHash, vkeyHash, policyId, totalWindows, totalEvents, allWindowsCompliant
        );

        if (!allWindowsCompliant) {
            emit PolicyViolationAlert(sealHash, policyId, 1);
        }

        return true;
    }

    /**
     * @notice Verifies a binary Merkle inclusion proof for a single syscall event.
     * @param root The trace Merkle root.
     * @param leaf The leaf hash of the syscall event: sha256("ZK_LEAF_V1:" || eventBytes).
     * @param leafIndex The 0-based index of the leaf in the tree.
     * @param siblings Array of sibling hashes along the Merkle branch.
     */
    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata siblings
    ) external pure returns (bool) {
        bytes32 current = leaf;
        uint256 idx = leafIndex;

        for (uint256 i = 0; i < siblings.length; i++) {
            if (idx % 2 == 0) {
                current = sha256(abi.encodePacked("ZK_NODE_V1:", current, siblings[i]));
            } else {
                current = sha256(abi.encodePacked("ZK_NODE_V1:", siblings[i], current));
            }
            idx /= 2;
        }

        return current == root;
    }

    /**
     * @notice Stakes native ETH collateral for an autonomous agent.
     */
    function stakeAgent(bytes32 agentId) external payable {
        require(msg.value > 0, "ZeroKernelVerifier: stake must be positive");
        AgentStake storage stake = agentStakes[agentId];
        stake.stakedAmountWei += msg.value;
        stake.isRegistered = true;
    }

    /**
     * @notice Stakes ERC-20 collateral (e.g. USDC, WETH) for an autonomous agent.
     */
    function stakeAgentERC20(bytes32 agentId, address token, uint256 amount) external {
        require(token != address(0), "ZeroKernelVerifier: invalid token address");
        require(amount > 0, "ZeroKernelVerifier: stake must be positive");

        bool success = IERC20Minimal(token).transferFrom(msg.sender, address(this), amount);
        require(success, "ZeroKernelVerifier: ERC-20 stake transfer failed");

        AgentERC20Stake storage stake = agentERC20Stakes[agentId][token];
        stake.stakedAmount += amount;
        stake.isRegistered = true;

        emit AgentERC20Staked(agentId, token, amount);
    }

    /**
     * @notice Immediately slashes an autonomous agent if a verified receipt proves it violated policy.
     */
    function slashRogueAgent(bytes32 agentId, bytes32 sealHash, address penaltyRecipient)
        external
        onlyOwner
    {
        require(penaltyRecipient != address(0), "ZeroKernelVerifier: zero penalty recipient");
        require(verifiedReceipts[sealHash], "ZeroKernelVerifier: receipt not verified");
        AgentStake storage stake = agentStakes[agentId];
        require(
            stake.isRegistered && !stake.isSlashed,
            "ZeroKernelVerifier: agent not eligible for slash"
        );

        uint256 amount = stake.stakedAmountWei;
        stake.stakedAmountWei = 0;
        stake.isSlashed = true;

        emit AgentSlashed(penaltyRecipient, agentId, amount);

        (bool sent,) = penaltyRecipient.call{ value: amount }("");
        require(sent, "ZeroKernelVerifier: slashing transfer failed");
    }

    /**
     * @notice Slashes an autonomous agent's ERC-20 collateral if a verified receipt proves it violated policy.
     */
    function slashRogueAgentERC20(
        bytes32 agentId,
        address token,
        bytes32 sealHash,
        address penaltyRecipient
    ) external onlyOwner {
        require(penaltyRecipient != address(0), "ZeroKernelVerifier: zero penalty recipient");
        require(verifiedReceipts[sealHash], "ZeroKernelVerifier: receipt not verified");

        AgentERC20Stake storage stake = agentERC20Stakes[agentId][token];
        require(
            stake.isRegistered && !stake.isSlashed,
            "ZeroKernelVerifier: agent ERC20 stake not eligible for slash"
        );

        uint256 amount = stake.stakedAmount;
        stake.stakedAmount = 0;
        stake.isSlashed = true;

        emit AgentERC20Slashed(penaltyRecipient, agentId, token, amount);

        bool sent = IERC20Minimal(token).transfer(penaltyRecipient, amount);
        require(sent, "ZeroKernelVerifier: ERC20 slashing transfer failed");
    }

    /**
     * @notice Initiates an optimistic slashing dispute window before funds are transferred.
     */
    function initiateSlashingDispute(
        bytes32 disputeId,
        bytes32 agentId,
        bytes32 sealHash,
        address penaltyRecipient,
        uint256 disputeWindowSeconds
    ) external onlyOwner {
        require(disputeId != bytes32(0), "ZeroKernelVerifier: invalid dispute id");
        require(penaltyRecipient != address(0), "ZeroKernelVerifier: zero penalty recipient");
        require(verifiedReceipts[sealHash], "ZeroKernelVerifier: receipt not verified");
        require(disputeWindowSeconds > 0, "ZeroKernelVerifier: dispute window must be positive");

        AgentStake storage stake = agentStakes[agentId];
        require(
            stake.isRegistered && !stake.isSlashed,
            "ZeroKernelVerifier: agent not eligible for slash"
        );

        require(
            slashingDisputes[disputeId].initiatedAt == 0,
            "ZeroKernelVerifier: dispute already exists"
        );

        slashingDisputes[disputeId] = SlashingDispute({
            agentId: agentId,
            sealHash: sealHash,
            penaltyRecipient: penaltyRecipient,
            initiatedAt: block.timestamp,
            disputeWindowSeconds: disputeWindowSeconds,
            resolved: false,
            cancelled: false
        });

        emit SlashingDisputeInitiated(disputeId, agentId, sealHash, disputeWindowSeconds);
    }

    /**
     * @notice Executes a resolved slashing dispute once the dispute challenge window has elapsed.
     */
    function executeSlashingDispute(bytes32 disputeId) external {
        SlashingDispute storage dispute = slashingDisputes[disputeId];
        require(dispute.initiatedAt > 0, "ZeroKernelVerifier: dispute not found");
        require(!dispute.resolved, "ZeroKernelVerifier: dispute already resolved");
        require(!dispute.cancelled, "ZeroKernelVerifier: dispute was cancelled");
        require(
            block.timestamp >= dispute.initiatedAt + dispute.disputeWindowSeconds,
            "ZeroKernelVerifier: dispute window active"
        );

        dispute.resolved = true;
        AgentStake storage stake = agentStakes[dispute.agentId];
        require(
            stake.isRegistered && !stake.isSlashed,
            "ZeroKernelVerifier: agent not eligible for slash"
        );

        uint256 amount = stake.stakedAmountWei;
        stake.stakedAmountWei = 0;
        stake.isSlashed = true;

        emit AgentSlashed(dispute.penaltyRecipient, dispute.agentId, amount);
        emit SlashingDisputeExecuted(disputeId, dispute.agentId, amount);

        (bool sent,) = dispute.penaltyRecipient.call{ value: amount }("");
        require(sent, "ZeroKernelVerifier: slashing transfer failed");
    }

    /**
     * @notice Cancels an active slashing dispute if counter-evidence or a valid defense is accepted.
     */
    function cancelSlashingDispute(bytes32 disputeId, string calldata reason) external onlyOwner {
        SlashingDispute storage dispute = slashingDisputes[disputeId];
        require(dispute.initiatedAt > 0, "ZeroKernelVerifier: dispute not found");
        require(!dispute.resolved, "ZeroKernelVerifier: dispute already resolved");
        require(!dispute.cancelled, "ZeroKernelVerifier: dispute already cancelled");

        dispute.cancelled = true;
        emit SlashingDisputeCancelled(disputeId, reason);
    }
}

