// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Semver } from "@eth-optimism/contracts-bedrock/contracts/universal/Semver.sol";

/**
 * @title AttestationStation
 * @author Optimism Collective
 * @author Gitcoin
 * @notice Where attestations live.
 */
contract AttestationStation is Semver {
    /**
     * @notice Emitted when Attestation is created.
     *
     * @param creator Address that made the attestation.
     * @param about   Address attestation is about.
     * @param key     Key of the attestation.
     * @param val     Value of the attestation.
     */
    event AttestationCreated(
        address indexed creator,
        address indexed about,
        bytes32 indexed key,
        bytes val
    );

    /**
     * @notice Struct representing data that is being attested.
     *
     * @custom:field about Address for which the attestation is about.
     * @custom:field key   A bytes32 key for the attestation.
     * @custom:field val   The attestation as arbitrary bytes.
     */
    struct AttestationData {
        address about;
        bytes32 key;
        bytes val;
    }

    /**
     * @notice Maps addresses to attestations. Creator => About => Key => Value.
     */
    mapping(address => mapping(address => mapping(bytes32 => bytes))) public attestations;

    /**
     * @notice
     */
    bytes32 public constant TX_TYPEHASH =
        keccak256("PermitAttest(address about, bytes32 key, bytes about)");

    /**
     * @notice
     */
    bytes32 public _DOMAIN_SEPARATOR;

    /**
     * @custom:semver 1.2.0
     */
    constructor() Semver(1, 2, 0) {
        bytes32 hash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                hash,
                keccak256("AttestationStation"),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Allows anyone to create an attestation.
     *
     * @param _about Address that the attestation is about.
     * @param _key   A key used to namespace the attestation.
     * @param _val   An arbitrary value stored as part of the attestation.
     */
    function attest(
        address _about,
        bytes32 _key,
        bytes memory _val
    ) public {
        attestations[msg.sender][_about][_key] = _val;

        emit AttestationCreated(msg.sender, _about, _key, _val);
    }

    /**
     * @notice Allows anyone to create attestations.
     *
     * @param _attestations An array of attestation data.
     */
    function attest(AttestationData[] calldata _attestations) external {
        uint256 length = _attestations.length;
        for (uint256 i = 0; i < length; ) {
            AttestationData memory attestation = _attestations[i];

            attest(attestation.about, attestation.key, attestation.val);

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Allows a smart contract to attest on behalf of a user using EIP-712
     *
     * @param _about Address that the attestation is about.
     * @param _key   A key used to namespace the attestation.
     * @param _val   An arbitrary value stored as part of the attestation.
     * @param _v     EIP712 ECDSA recovery parameter.
     * @param _r     EIP712 ECDSA `r` value.
     * @param _s     EIP712 ECDSA `s` value.
     */
    function permitAttest(
        address _about,
        bytes32 _key,
        bytes memory _val,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external {
        address sender = ecrecover712(_about, _key, _val, _v, _r, _s);
        attestations[sender][_about][_key] = _val;

        emit AttestationCreated(sender, _about, _key, _val);
    }

    /**
     * @notice
     */
    function ecrecover712(
        address _about,
        bytes32 _key,
        bytes memory _val,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal view returns (address) {
        bytes32 hashStruct = keccak256(abi.encode(TX_TYPEHASH, _about, _key, _val));
        bytes32 h = keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, hashStruct));
        address signer = ecrecover(h, _v, _r, _s);
        require(signer != address(0), "AttestationStation: invalid signature");
        return signer;
    }
}
