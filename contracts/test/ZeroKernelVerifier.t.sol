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
}
