#!/usr/bin/env python3
"""
ZeroKernel On-Chain Agent Governance & Slashing Simulator

Demonstrates the complete decentralized governance lifecycle:
1. Agent Staking: Agent operator stakes collateral into ZeroKernelVerifier.sol
2. Compliant Auditing: Agent executes within security policies, emits zkVM receipt, verifies on-chain
3. Rogue Detection: Agent attempts forbidden C2 exfiltration (port 6667 / forbidden subnet)
4. Proof-of-Violation: zkVM circuit catches invariant violation, emits tamper-proof seal
5. On-Chain Slashing: verifier marks receipt, burns/transfers staked collateral to penalty recipient
"""

import sys
import os
import json
import hashlib
import time

# Ensure sdk/python is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from zerokernel import ZeroKernelClient, ZeroKernelVerifier, SecurityPolicy


class MockOnChainVerifier:
    def __init__(self):
        self.verified_receipts = set()
        self.agent_stakes = {}
        self.slashed_agents = set()
        self.treasury_balance = 0
        self.registered_policies = {
            202601: "Default ZeroKernel Kernel Invariants",
            2002: "Autonomous Agent Egress & C2 Defense",
        }

    def stake_agent(self, agent_id: str, amount_eth: float):
        if agent_id not in self.agent_stakes:
            self.agent_stakes[agent_id] = 0.0
        self.agent_stakes[agent_id] += amount_eth
        print(f"  [EVM Event] AgentStaked: agent={agent_id}, amount={amount_eth} ETH (Total: {self.agent_stakes[agent_id]} ETH)")

    def verify_receipt(self, receipt_dict: dict) -> bool:
        commitment = receipt_dict["public_commitment"]
        seal = receipt_dict["proof_seal_hex"]
        policy_id = commitment["policy_id"]

        if seal in self.verified_receipts:
            print("  [EVM Revert] Receipt already verified!")
            return False

        if policy_id not in self.registered_policies:
            print(f"  [EVM Revert] Unregistered policy {policy_id}!")
            return False

        self.verified_receipts.add(seal)
        print(f"  [EVM Event] ReceiptVerified: seal=0x{seal[:16]}... policy={policy_id} events={commitment['total_events_verified']} compliant={commitment['policy_compliant']}")
        if not commitment["policy_compliant"]:
            print(f"  [EVM Alert] PolicyViolationAlert: seal=0x{seal[:16]}... violations={commitment['violations_detected']}")
        return True

    def slash_rogue_agent(self, agent_id: str, seal: str, penalty_recipient: str) -> bool:
        if seal not in self.verified_receipts:
            print("  [EVM Revert] Proof receipt not verified on-chain!")
            return False

        if agent_id not in self.agent_stakes or self.agent_stakes[agent_id] == 0:
            print(f"  [EVM Revert] Agent {agent_id} has no active stake!")
            return False

        if agent_id in self.slashed_agents:
            print(f"  [EVM Revert] Agent {agent_id} already slashed!")
            return False

        slashed_amount = self.agent_stakes[agent_id]
        self.agent_stakes[agent_id] = 0.0
        self.slashed_agents.add(agent_id)
        self.treasury_balance += slashed_amount

        print(f"  [EVM Event] AgentSlashed: agent={agent_id}, penalty_recipient={penalty_recipient}, slashed={slashed_amount} ETH")
        return True


def run_demo():
    print("=" * 70)
    print("ZeroKernel: Autonomous Agent On-Chain Governance & Slashing Demo")
    print("=" * 70)

    client = ZeroKernelClient()
    evm = MockOnChainVerifier()

    agent_id = "autonomous-trader-01"
    penalty_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

    # Step 1: Agent stakes 10 ETH into ZeroKernelVerifier.sol
    print("\n[Step 1] Autonomous Agent Staking Collateral on EVM:")
    evm.stake_agent(agent_id, 10.0)

    # Step 2: Agent executes compliant operation
    print("\n[Step 2] Auditing Compliant Agent Lifecycle (64 steps):")
    benign_receipt = client.audit_agent(agent_id=agent_id, lifecycle_steps=64, inject_exfiltration=False)
    print(f"  zkVM Prover: {benign_receipt.prover_backend}")
    print(f"  Events Verified: {benign_receipt.public_commitment.total_events_verified}")
    print(f"  Policy Compliant: {benign_receipt.public_commitment.policy_compliant}")
    print(f"  Proof Seal: {benign_receipt.proof_seal_hex[:24]}...")

    # Step 3: Submit benign receipt on-chain
    print("\n[Step 3] Submitting Proof Receipt to ZeroKernelVerifier.sol:")
    receipt_data = {
        "version": benign_receipt.version,
        "prover_backend": benign_receipt.prover_backend,
        "vkey_hash": benign_receipt.vkey_hash,
        "public_commitment": {
            "policy_id": benign_receipt.public_commitment.policy_id,
            "total_events_verified": benign_receipt.public_commitment.total_events_verified,
            "violations_detected": benign_receipt.public_commitment.violations_detected,
            "window_start_ns": benign_receipt.public_commitment.window_start_ns,
            "window_end_ns": benign_receipt.public_commitment.window_end_ns,
            "trace_merkle_root": benign_receipt.public_commitment.trace_merkle_root,
            "policy_compliant": benign_receipt.public_commitment.policy_compliant,
        },
        "commitment_merkle_hex": benign_receipt.commitment_merkle_hex,
        "proof_seal_hex": benign_receipt.proof_seal_hex,
        "proving_time_ms": benign_receipt.proving_time_ms,
    }
    assert evm.verify_receipt(receipt_data)
    print("  Agent stake remains 10.0 ETH; reputation intact.")

    # Step 4: Agent attempts rogue behavior (C2 port 6667 exfiltration)
    print("\n[Step 4] Auditing Rogue Agent Executing Exfiltration Attempt:")
    rogue_receipt = client.audit_agent(agent_id=agent_id, lifecycle_steps=64, inject_exfiltration=True)
    print(f"  Events Verified: {rogue_receipt.public_commitment.total_events_verified}")
    print(f"  Violations Caught: {rogue_receipt.public_commitment.violations_detected}")
    print(f"  Policy Compliant: {rogue_receipt.public_commitment.policy_compliant}")
    print(f"  Proof Seal: {rogue_receipt.proof_seal_hex[:24]}...")

    # Step 5: Submit proof of violation to smart contract
    print("\n[Step 5] Submitting Proof of Violation to ZeroKernelVerifier.sol:")
    rogue_receipt_data = {
        "version": rogue_receipt.version,
        "prover_backend": rogue_receipt.prover_backend,
        "vkey_hash": rogue_receipt.vkey_hash,
        "public_commitment": {
            "policy_id": rogue_receipt.public_commitment.policy_id,
            "total_events_verified": rogue_receipt.public_commitment.total_events_verified,
            "violations_detected": rogue_receipt.public_commitment.violations_detected,
            "window_start_ns": rogue_receipt.public_commitment.window_start_ns,
            "window_end_ns": rogue_receipt.public_commitment.window_end_ns,
            "trace_merkle_root": rogue_receipt.public_commitment.trace_merkle_root,
            "policy_compliant": rogue_receipt.public_commitment.policy_compliant,
        },
        "commitment_merkle_hex": rogue_receipt.commitment_merkle_hex,
        "proof_seal_hex": rogue_receipt.proof_seal_hex,
        "proving_time_ms": rogue_receipt.proving_time_ms,
    }
    assert evm.verify_receipt(rogue_receipt_data)

    # Step 6: Trigger on-chain slashing
    print("\n[Step 6] Calling slashRogueAgent() on ZeroKernelVerifier.sol:")
    slashed = evm.slash_rogue_agent(agent_id, rogue_receipt.proof_seal_hex, penalty_recipient)
    assert slashed

    print("\n[Step 7] Final Governance Accounting:")
    print(f"  Agent Stake: {evm.agent_stakes[agent_id]} ETH (Slashed)")
    print(f"  Penalty Recipient / Bounty Pool Balance: {evm.treasury_balance} ETH")
    print("=" * 70)
    print("SUCCESS: Full on-chain autonomous agent governance demo verified!")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()

