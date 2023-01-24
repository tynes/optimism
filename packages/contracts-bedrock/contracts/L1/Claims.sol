// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Predeploys } from "../libraries/Predeploys.sol";
import { Types } from "../libraries/Types.sol";
import { Hashing } from "../libraries/Hashing.sol";
import { SafeCall } from "../libraries/SafeCall.sol";
import { OptimismPortal } from "./OptimismPortal.sol";

/**
 * Open questions:
 *  - specifically making state claims right now to allow for other types of
 *    claims in the future
 *  - how to top up the bond?
 * TODOs:
 *  - events
 *  - dispute game inteface in dispute-game-contracts repo
 *  - define fault proof vm interface (should also work with validity proofs)
 */


/**
 * General functionality:
 *  - make arbitrary claims about state
 *  - claims are based on a L2 block hash, account key + value
 *  - bonds are held in this contract
 *  - currently reverts when claims not made about withdrawals, leaves open the
 *    door for alternatives in the future
 */
contract Claims {

    struct StateClaim {
        // storage slot value
        bytes32 value;
        // time the claim was made
        uint256 timestamp;
        // the amount of wei bonded
        uint256 bond;
        // account making the claim
        address sender;
    }

    // mapping of L2BlockHash to address to key to state claim
    mapping(bytes32 => mapping(address => mapping(bytes32 => StateClaim))) public claims;

    // only the challenger contract can remove state claims
    address immutable CHALLENGER;

    // the optimistic finalization period
    uint256 immutable FINALIZATION_PERIOD_SECONDS;

    constructor(address _challenger, uint256 _finalizationPeriodSeconds) {
        CHALLENGER = _challenger;
        FINALIZATION_PERIOD_SECONDS = _finalizationPeriodSeconds;
    }
        //  - remove time checking logic

    // At a given L2 blocknumber, make a claim about an accounts storage by
    // key/value
    function makeStateClaim(bytes32 _l2BlockHash, address _addr, bytes32 _key, bytes32 _value) public payable {
        // TODO: temporary, only allow claims about withdrawals
        require(_addr == Predeploys.L2_TO_L1_MESSAGE_PASSER);

        // ensure that the value is large enough to cover the bond
        require(msg.value >= bondSize());

        claims[_l2BlockHash][_addr][_key] = StateClaim({
            value: _value,
            timestamp: block.timestamp,
            bond: msg.value,
            sender: msg.sender
        });
    }

    function finalizeStateClaim(bytes32 _l2BlockHash, address _addr, bytes32 _key) public {
        StateClaim memory claim = claims[_l2BlockHash][_addr][_key];

        // ensure that the claim has been finalized
        require(FINALIZATION_PERIOD_SECONDS + claim.timestamp >= block.timestamp);

        // prevent double claims + reentrancy guard
        // persist the value so that it can continue to be used
        claims[_l2BlockHash][_addr][_key] = StateClaim({
            value: claim.value,
            timestamp: 0,
            bond: 0,
            sender: claim.sender
        });

        // send the bond back to whoever made it because it has been finalized
        bool success = SafeCall.call({
            _target: claim.sender,
            _gas: gasleft(),
            _value: claim.bond,
            _calldata: hex""
        });

        // ensure the call goes through to prevent stuck ether
        require(success);
    }

    // the game would be able to remove state claim in the permissionless case
    function removeStateClaim(bytes32 _l2BlockHash, address _addr, bytes32 _key) public {
        // only the challenger can remove state claims
        require(msg.sender == CHALLENGER);

        // read the claim into memory so that we can know when it was claimed
        // and how large the bond was
        StateClaim memory claim = claims[_l2BlockHash][_addr][_key];

        // ensure that the claim has not been finalized
        require(FINALIZATION_PERIOD_SECONDS + claim.timestamp < block.timestamp);

        // remove the claim from the state
        delete claims[_l2BlockHash][_addr][_key];

        // send the bond to the caller, in this case it is the CHALLENGER
        bool success = SafeCall.call({
            _target: msg.sender,
            _gas: gasleft(),
            _value: claim.bond,
            _calldata: hex""
        });

        // ensure the call is successful to prevent ether from being locked
        require(success);
    }

    // TODO: some formula for this
    function bondSize() public pure returns (uint256) {
        return 0;
    }
}

/**
 * A higher level construction on top of Claims, specifically for withdrawals
 * Users interact with this for managing withdrawals
 * TODO: consider alterations in withdrawal hashing, do we want to enforce
 *       hashing on chain or just pass in the hash?
 * - consider making part of Portal itself
 */
contract WithdrawalClaims {
    Claims immutable CLAIMS;
    OptimismPortal immutable PORTAL;

    constructor(address _claims, address payable _portal) {
        CLAIMS = Claims(_claims);
        PORTAL = OptimismPortal(_portal);
    }

    // we can forward the Portal `proveWithdrawalTransaction` to call this to
    // stay more backwards compatible
    function claimWithdrawalTransaction(Types.WithdrawalTransaction memory _tx, bytes32 _l2BlockHash) public payable {
        // compute the withdrawal hash
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);

        // compute the storage slot
        // TODO: create a higher level helper for this
        bytes32 storageKey = keccak256(
            abi.encode(
                withdrawalHash,
                uint256(0)
            )
        );

        // call the Claims contract with the correct schema
        CLAIMS.makeStateClaim{ value: msg.value }({
            _l2BlockHash: _l2BlockHash,
            _addr: Predeploys.L2_TO_L1_MESSAGE_PASSER,
            _key: storageKey,
            _value: hex"01"
        });
    }

    function claimWithdrawalTransaction(bytes32 _withdrawalHash, bytes32 _l2BlockHash) public payable {
        bytes32 storageKey = keccak256(
            abi.encode(
                withdrawalHash,
                uint256(0)
            )
        );

        // call the Claims contract with the correct schema
        CLAIMS.makeStateClaim{ value: msg.value }({
            _l2BlockHash: _l2BlockHash,
            _addr: Predeploys.L2_TO_L1_MESSAGE_PASSER,
            _key: storageKey,
            _value: hex"01"
        });
    }

    // TODO: maybe we want the interface to be on withdrawalHash
    function finalizeWithdrawalTransaction(Types.WithdrawalTransaction memory _tx, bytes32 _l2BlockHash) public {
        // compute the withdrawal hash
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);

        // compute the storage slot
        // TODO: create a higher level helper for this
        bytes32 storageKey = keccak256(
            abi.encode(
                withdrawalHash,
                uint256(0)
            )
        );

        // This reverts if the claim is not finalized
        // adds reentrancy protection
        // returns the bond to the user
        CLAIMS.finalizeStateClaim({
            _l2BlockHash: _l2BlockHash,
            _addr: Predeploys.L2_TO_L1_MESSAGE_PASSER,
            _key: storageKey
        });

        // Update the portal to:
        //  - only allow this contract to call `finalizeWithdrawalTransaction`
        //  - remove all time checking logic
        PORTAL.finalizeWithdrawalTransaction(_tx);
    }
}

/**
 * Can act as a Challenger for Claims
 * Based on a threshold
 */
contract ThresholdClaimsChallenger {
    // represented as a percentage
    uint256 public immutable QUORUM_RATIO;
    // can add or remove challenges
    address public immutable MANAGER;
    // address of Claims contract
    Claims public immutable CLAIMS;
    // 2 decimals
    uint256 scalar constant = 100;
    // track the number of challengers
    uint256 challengerCount;
        //  - remove time checking logic
    // the challengers that can remove state claims
    mapping(address => bool) challengers;
    // mapping of challenge counts by L2 block number to account to slot
    mapping(bytes32 => mapping(address => mapping(bytes32 => uint256))) challenges;

    constructor(address _claims, address _manager, uint256 _ratio, address[] memory _challengers) {
        CLAIMS = Claims(_claims);
        QUORUM_RATIO = _ratio;
        MANAGER = _manager;

        uint256 length = _challengers.length;

        require(length != 0);

        for (uint256 i; i < length; i++) {
            challengers[_challengers[i]];
        }
        challengerCount = length;
    }

    // allow adding or removing challengers from the set
    // do not allow removal of all challengers
    function setChallenger(address _addr, bool _status) public {
        require(msg.sender == MANAGER);

        challengers[_addr] = _status;

        if (_status) {
            challengerCount++;
        } else {
            challengerCount--;
        }

        require(challengerCount != 0);
    }

    // race condition prone? break into challenge + finalize?
    // TODO: make this eip712 based
    function challengeStateClaim(bytes32 _l2BlockHash, address _addr, bytes32 _key) public {
        require(challengers[msg.sender] == true);

        uint256 attestations = challenges[_l2BlockHash][_addr][_key];
        attestations++;

        // execute the challenge if its over the threshold
        // else update the challenge state
        if ((attestations * scalar) / challengerCount >= QUORUM_RATIO) {
            CLAIMS.removeStateClaim({
                _l2BlockHash: _l2BlockHash,
                _addr: _addr,
                _key: _key
            });

            challenges[_l2BlockHash][_addr][_key] = 0;
        } else {
            challenges[_l2BlockHash][_addr][_key] = attestations;
        }
    }
}

// Give a nice high level api for challenging withdrawals
contract WithdrawalClaimsChallenger is ThresholdClaimsChallenger {
    constructor(
        address _claims,
        address _manager,
        uint256 _ratio,
        address[] memory _challengers
    ) ThresholdClaimsChallenger(_claims, _manager, _ratio, _challengers) {}

    // compute the withdrawal hash onchain
    function challengeWithdrawalTransaction(Types.WithdrawalTransaction memory _tx, bytes32 _l2BlockHash) public {
        // compute the withdrawal hash
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);

        // compute the storage slot
        bytes32 storageKey = keccak256(
            abi.encode(
                withdrawalHash,
                uint256(0)
            )
        );

        challengeStateClaim({
            _l2BlockHash: _l2BlockHash,
            _addr: Predeploys.L2_TO_L1_MESSAGE_PASSER,
            _key: storageKey
        });
    }

    // compute the withdrawalHash offchain
    function challengeWithdrawalTransaction(bytes32 withdrawalHash, bytes32 _l2BlockHash) public {
        bytes32 storageKey = keccak256(
            abi.encode(
                withdrawalHash,
                uint256(0)
            )
        );

        challengeStateClaim({
            _l2BlockHash: _l2BlockHash,
            _addr: Predeploys.L2_TO_L1_MESSAGE_PASSER,
            _key: storageKey
        });
    }
}
