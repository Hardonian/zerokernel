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

    function setUp() public {
        verifier = new ZeroKernelVerifier();
    }

    function testDefaultPolicyRegistered() public view {
        (bytes32 vkey, bool active, ) = verifier.policies(202601);
        require(active, "Default policy must be active");
        require(vkey == 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a, "VKey mismatch");
    }

    function testVerifyReceiptSmoke() public {
        bytes32 vkey = 0x6defd5edeed159f669924b211fb42fe437b7e11dacdc43bff0cc147b45570a5a;
        bytes32 merkleRoot = 0xade0de4f3eca59315848705181ba5401ea33b010c065f351d23a43d0feaa9b6e;
        bytes32 seal = 0xb9fa7936e8acf486e31fb86081e8b6eefb7ad4895bb4d6bc1096c0dd5d99deca;

        bool success = verifier.verifyReceipt(
            vkey,
            merkleRoot,
            202601,
            4096,
            true,
            abi.encodePacked(seal)
        );
        require(success, "Receipt must verify");
        require(verifier.verifiedReceipts(seal), "Receipt should be marked verified");
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
}

