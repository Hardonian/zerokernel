// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "../ZeroKernelVerifier.sol";

contract DeployZeroKernelVerifier {
    function run() external returns (ZeroKernelVerifier verifier) {
        verifier = new ZeroKernelVerifier();
    }
}

