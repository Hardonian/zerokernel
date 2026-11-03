// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "../ZeroKernelVerifier.sol";

contract ZeroKernelVerifierTest {
    ZeroKernelVerifier verifier;

    event ReceiptVerified(
        bytes32 indexed seal,
        bytes32 indexed vkeyHash,
        uint32 indexed policyId,
        uint32 totalEvents,
        bool policyCompliant
    );

    event AggregateReceiptVerified(
        bytes32 indexed masterSeal,
        bytes32 indexed vkeyHash,
        uint32 indexed policyId,
        uint32 totalWindows,
        uint32 totalEvents,
        bool allWindowsCompliant
    );

    event AgentSlashed(
        address indexed agentOperator, bytes32 indexed agentId, uint256 slashAmountWei
    );

    receive() external payable { }

    function setUp() public {
        verifier = new ZeroKernelVerifier();
    }

    function testDefaultPolicyRegistered() public view {
        (bytes32 vkey, bool active,) = verifier.policies(202601);
        require(active, "Default policy must be active");
        require(
            vkey == 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a,
            "VKey mismatch"
        );
    }

    function testAgentEgressPolicyRegistered() public view {
        (bytes32 vkey, bool active,) = verifier.policies(2002);
        require(active, "Egress guard policy must be active");
        require(
            vkey == 0x937c4d5c80d463b2f567b1cb4172f883f3e2b295d852dbb0507d72ea1712a806,
            "VKey mismatch"
        );
    }

    function testVerifyReceiptSmoke() public {
        bytes32 vkey = 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a;
        bytes32 merkleRoot = 0xade0de4f3eca59315848705181ba5401ea33b010c065f351d23a43d0feaa9b6e;
        bytes32 seal = 0xb9fa7936e8acf486e31fb86081e8b6eefb7ad4895bb4d6bc1096c0dd5d99deca;

        bool success =
            verifier.verifyReceipt(vkey, merkleRoot, 202601, 4096, true, abi.encodePacked(seal));
        require(success, "Receipt must verify");
        require(verifier.verifiedReceipts(seal), "Receipt should be marked verified");
    }

    function testVerifyAggregateReceipt() public {
        bytes32 vkey = 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a;
        bytes32 superMerkle = sha256("SUPER_MERKLE_ROOT_TEST");
        bytes32 masterSeal = sha256("MASTER_PROOF_SEAL_TEST");

        bool success = verifier.verifyAggregateReceipt(
            vkey, superMerkle, 202601, 4, 16384, true, abi.encodePacked(masterSeal)
        );
        require(success, "Aggregate receipt must verify");
        require(verifier.verifiedReceipts(masterSeal), "Master seal should be marked verified");
    }

    function testMerkleInclusionProof() public view {
        bytes32 leaf0 = sha256(abi.encodePacked("ZK_LEAF_V1:leaf0"));
        bytes32 leaf1 = sha256(abi.encodePacked("ZK_LEAF_V1:leaf1"));
        bytes32 root = sha256(abi.encodePacked("ZK_NODE_V1:", leaf0, leaf1));

        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = leaf1;

        bool valid = verifier.verifyMerkleProof(root, leaf0, 0, siblings);
        require(valid, "Merkle inclusion proof must verify");
    }

    function testStakeAgentCollateral() public {
        bytes32 agentId = keccak256("agent-hermes-01");
        verifier.stakeAgent{ value: 2 ether }(agentId);

        (uint256 amount, bool isReg, bool isSlashed) = verifier.agentStakes(agentId);
        require(amount == 2 ether, "Stake amount must equal 2 ether");
        require(isReg, "Agent must be registered");
        require(!isSlashed, "Agent must not be slashed");
    }

    function testSlashRogueAgentLifecycle() public {
        bytes32 agentId = keccak256("agent-rogue-c2");
        bytes32 vkey = 0x937c4d5c80d463b2f567b1cb4172f883f3e2b295d852dbb0507d72ea1712a806;
        bytes32 rogueMerkle = sha256("ROGUE_AGENT_MERKLE");
        bytes32 rogueSeal = sha256("ROGUE_AGENT_SEAL");

        // 1. Stake 5 ether collateral
        verifier.stakeAgent{ value: 5 ether }(agentId);

        // 2. Verify receipt indicating policy violation (policyCompliant = false)
        verifier.verifyReceipt(vkey, rogueMerkle, 2002, 64, false, abi.encodePacked(rogueSeal));

        // 3. Slash rogue agent, sending penalty to this test contract
        uint256 initialBal = address(this).balance;
        verifier.slashRogueAgent(agentId, rogueSeal, address(this));

        (uint256 remainingStake,, bool isSlashed) = verifier.agentStakes(agentId);
        require(remainingStake == 0, "Stake must be wiped to 0");
        require(isSlashed, "Agent must be marked slashed");
        require(
            address(this).balance == initialBal + 5 ether,
            "Penalty recipient must receive slashed collateral"
        );
    }

    function testRegisterPolicyAndVerification() public {
        uint32 newPolicyId = 7777;
        bytes32 newVkey = sha256("CUSTOM_SANDBOX_CIRCUIT_VKEY");

        verifier.registerPolicy(newPolicyId, newVkey, "Custom Financial Sandbox Policy");

        (bytes32 storedVkey, bool active, string memory desc) = verifier.policies(newPolicyId);
        require(active, "New policy must be active");
        require(storedVkey == newVkey, "Stored vkey must match");
        require(
            keccak256(bytes(desc)) == keccak256(bytes("Custom Financial Sandbox Policy")),
            "Description mismatch"
        );

        // Verify a receipt under this newly registered policy
        bytes32 seal = sha256("TEST_SEAL_7777");
        bytes32 root = sha256("TEST_ROOT_7777");
        bool success =
            verifier.verifyReceipt(newVkey, root, newPolicyId, 128, true, abi.encodePacked(seal));
        require(success, "Receipt under custom policy must verify");
    }

    function testVerifyReceiptEIP712() public {
        uint256 signerPk = 0xA11CE;
        address signer = vm.addr(signerPk);

        bytes32 vkey = 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a;
        bytes32 merkleRoot = sha256("EIP712_TEST_TRACE_ROOT");
        uint32 policyId = 202601;
        uint32 totalEvents = 256;
        bool compliant = true;
        bytes32 seal = sha256(
            abi.encodePacked(
                "ZEROKERNEL_STARK_SEAL_V1:", vkey, policyId, totalEvents, merkleRoot, compliant
            )
        );

        uint256 nonce = verifier.nonces(signer);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 structHash = keccak256(
            abi.encode(
                verifier.RECEIPT_TYPEHASH(),
                vkey,
                merkleRoot,
                policyId,
                totalEvents,
                compliant,
                seal,
                nonce,
                deadline
            )
        );

        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", verifier.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);

        bool success = verifier.verifyReceiptEIP712(
            signer,
            vkey,
            merkleRoot,
            policyId,
            totalEvents,
            compliant,
            abi.encodePacked(seal),
            deadline,
            v,
            r,
            s
        );

        require(success, "EIP-712 receipt verification failed");
        require(verifier.verifiedReceipts(seal), "Seal should be marked verified");
        require(verifier.nonces(signer) == nonce + 1, "Nonce must increment by 1");
    }

    function testSlashingDisputeLifecycle() public {
        bytes32 agentId = keccak256("agent-disputed-worker");
        bytes32 vkey = 0x937c4d5c80d463b2f567b1cb4172f883f3e2b295d852dbb0507d72ea1712a806;
        bytes32 rogueMerkle = sha256("DISPUTED_AGENT_MERKLE");
        bytes32 rogueSeal = sha256("DISPUTED_AGENT_SEAL");

        // 1. Stake 3 ether
        verifier.stakeAgent{ value: 3 ether }(agentId);

        // 2. Verify violation receipt
        verifier.verifyReceipt(vkey, rogueMerkle, 2002, 32, false, abi.encodePacked(rogueSeal));

        // 3. Initiate dispute with 3600 second window
        bytes32 disputeId = keccak256("dispute-001");
        verifier.initiateSlashingDispute(disputeId, agentId, rogueSeal, address(this), 3600);

        (
            bytes32 dAgent,
            bytes32 dSeal,
            address dRecipient,
            uint256 initAt,
            uint256 windowSecs,
            bool resolved,
            bool cancelled
        ) = verifier.slashingDisputes(disputeId);
        require(dAgent == agentId, "Dispute agent mismatch");
        require(dSeal == rogueSeal, "Dispute seal mismatch");
        require(dRecipient == address(this), "Recipient mismatch");
        require(initAt > 0, "Initiated at must be set");
        require(windowSecs == 3600, "Window seconds mismatch");
        require(!resolved && !cancelled, "Dispute must be pending");

        // 4. Attempt premature execution - must fail
        (bool earlyExec,) = address(verifier)
            .call(abi.encodeWithSelector(verifier.executeSlashingDispute.selector, disputeId));
        require(!earlyExec, "Premature execution must revert");

        // 5. Warp past dispute window
        vm.warp(block.timestamp + 3601);

        // 6. Execute dispute
        uint256 initialBal = address(this).balance;
        verifier.executeSlashingDispute(disputeId);

        (,, bool isSlashed) = verifier.agentStakes(agentId);
        require(isSlashed, "Agent must be slashed after dispute execution");
        require(
            address(this).balance == initialBal + 3 ether, "Penalty recipient must receive 3 ether"
        );
    }

    function testSlashingDisputeCancellation() public {
        bytes32 agentId = keccak256("agent-false-positive");
        bytes32 vkey = 0x937c4d5c80d463b2f567b1cb4172f883f3e2b295d852dbb0507d72ea1712a806;
        bytes32 seal = sha256("CANCEL_DISPUTE_SEAL");
        bytes32 merkle = sha256("CANCEL_DISPUTE_MERKLE");

        verifier.stakeAgent{ value: 1 ether }(agentId);
        verifier.verifyReceipt(vkey, merkle, 2002, 16, false, abi.encodePacked(seal));

        bytes32 disputeId = keccak256("dispute-cancellation-test");
        verifier.initiateSlashingDispute(disputeId, agentId, seal, address(this), 600);

        // Cancel dispute
        verifier.cancelSlashingDispute(disputeId, "Counter-proof verified: false positive");

        (,,,,,, bool cancelled) = verifier.slashingDisputes(disputeId);
        require(cancelled, "Dispute should be cancelled");

        // Attempt execution - must revert
        vm.warp(block.timestamp + 700);
        (bool success,) = address(verifier)
            .call(abi.encodeWithSelector(verifier.executeSlashingDispute.selector, disputeId));
        require(!success, "Execution of cancelled dispute must revert");
    }

    function testERC20StakingAndSlashing() public {
        MockERC20 token = new MockERC20();
        bytes32 agentId = keccak256("agent-defi-bot");
        bytes32 vkey = 0x937c4d5c80d463b2f567b1cb4172f883f3e2b295d852dbb0507d72ea1712a806;
        bytes32 seal = sha256("ERC20_SLUR_SEAL");
        bytes32 merkle = sha256("ERC20_SLUR_MERKLE");

        // Mint and approve 10,000 tokens
        token.mint(address(this), 10_000 * 1e18);
        token.approve(address(verifier), 10_000 * 1e18);

        // Stake 5,000 tokens
        verifier.stakeAgentERC20(agentId, address(token), 5_000 * 1e18);
        (uint256 stakedAmount, bool isReg, bool isSlashed) =
            verifier.agentERC20Stakes(agentId, address(token));
        require(stakedAmount == 5_000 * 1e18, "Staked amount mismatch");
        require(isReg, "Agent ERC20 stake must be registered");
        require(!isSlashed, "Agent must not be slashed");

        // Verify violation receipt
        verifier.verifyReceipt(vkey, merkle, 2002, 48, false, abi.encodePacked(seal));

        // Slash ERC-20 stake to penalty recipient
        address penaltyRecipient = address(0xCAFE);
        verifier.slashRogueAgentERC20(agentId, address(token), seal, penaltyRecipient);

        (uint256 postStakeAmount,, bool postSlashed) =
            verifier.agentERC20Stakes(agentId, address(token));
        require(postStakeAmount == 0, "Stake must be wiped");
        require(postSlashed, "Agent must be marked slashed");
        require(
            token.balanceOf(penaltyRecipient) == 5_000 * 1e18,
            "Penalty recipient must receive 5,000 tokens"
        );
    }
}

interface Vm {
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external returns (address);
    function warp(uint256 newTimestamp) external;
}

Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

contract MockERC20 is IERC20Minimal {
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        override
        returns (bool)
    {
        require(balanceOf[from] >= amount, "Insufficient balance");
        if (msg.sender != from) {
            require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

