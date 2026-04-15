// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    R3tardi0: an on-chain commit→reveal board that settles stakes through its own H0piuM vault.
    Design constraints:
    - No user-supplied constructor parameters (deploy-and-go).
    - No upgradeability or delegatecall.
    - Uses commit/reveal to reduce MEV games and front-running on submissions.
*/

import {H0piuM} from "./H0piuM.sol";

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library R3tardi0SafeTransfer {
    error R3tardi0__TokenCallFailed();
    error R3tardi0__TokenBadReturn();

    function _callOptionalReturn(address token, bytes memory data) private {
        (bool ok, bytes memory ret) = token.call(data);
        if (!ok) revert R3tardi0__TokenCallFailed();
        if (ret.length == 0) return;
        if (ret.length == 32) {
            uint256 v;
            assembly ("memory-safe") {
                v := mload(add(ret, 0x20))
            }
            if (v != 1) revert R3tardi0__TokenBadReturn();
            return;
        }
        revert R3tardi0__TokenBadReturn();
    }

    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.transferFrom.selector, from, to, amount));
    }

    function safeTransfer(address token, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.transfer.selector, to, amount));
    }

    function safeApprove(address token, address spender, uint256 amount) internal {
        // Some tokens require setting allowance to 0 first.
        (bool ok0, ) = token.call(abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), spender, 0));
        ok0;
        _callOptionalReturn(token, abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), spender, amount));
    }
}

contract R3tardi0 {
    using R3tardi0SafeTransfer for address;

    // --------- identity / constants ----------
    bytes32 internal constant _APP_FINGERPRINT =
        0x3d4f0a6b9c1e7a2d5f8b0c4e1a9d7c2f6b1a0d9e4c3b2a1f0e9d8c7b6a5f4e3d;
    bytes32 internal constant _RULESET_HASH =
        0x9a5f2c7d0b6e1f4a8c3d5e7b0a1c2d4e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c;

    // --------- indexing (for web UIs without log indexing) ----------
    uint256 internal constant _PAGE_MAX = 256;
    mapping(uint256 => bytes32[]) private _roundCommits;
    mapping(address => bytes32[]) private _authorCommits;
    mapping(uint256 => mapping(address => bytes32[])) private _roundAuthorCommits;

    // --------- EIP-712 reveal authorizations (gas sponsor / relayer) ----------
    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _EIP712_NAME_HASH = keccak256(bytes("R3tardi0-RevealRelay"));
    bytes32 internal constant _EIP712_VERSION_HASH = keccak256(bytes("v1.0.0"));
    bytes32 internal constant _REVEAL_AUTH_TYPEHASH =
        keccak256("RevealAuth(address author,uint256 roundId,bytes32 salt,bytes32 noteHash,bytes32 tagHash,uint256 deadline,uint256 nonce)");
    bytes32 internal constant _REVEAL_ERC20_AUTH_TYPEHASH =
        keccak256("RevealERC20Auth(address author,uint256 roundId,address token,bytes32 salt,bytes32 noteHash,bytes32 tagHash,uint256 deadline,uint256 nonce)");

    uint256 internal constant _SECP256K1_HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    error R3tardi0__AuthExpired();
    error R3tardi0__AuthBadSig();

    mapping(address => uint256) public revealNonces;

    event R3tardi0_RevealRelayed(uint256 indexed roundId, address indexed author, address indexed relayer, uint256 nonce);
    event R3tardi0_RevealRelayedERC20(uint256 indexed roundId, address indexed token, address indexed author, address relayer, uint256 nonce);

    // --------- analytics (on-chain summaries) ----------
    struct RoundTally {
        uint64 commitCount;
        uint64 revealCount;
        uint128 totalNativeStaked;
        uint128 totalNativeFees;
        uint128 totalNativeSlashed;
    }

    mapping(uint256 => RoundTally) public roundTally;
    mapping(uint256 => mapping(address => uint256)) public roundTokenStaked;
    mapping(uint256 => mapping(address => uint256)) public roundTokenFees;
    mapping(uint256 => mapping(address => uint256)) public roundTokenSlashed;

    struct RoundCaps {
        uint96 minStakeNative;
        uint96 minStakeErc20;
        uint32 maxCommitsPerAuthor;
        bool allowErc20;
    }

    mapping(uint256 => RoundCaps) public roundCaps;
    mapping(uint256 => mapping(address => uint32)) public roundAuthorCommitCount32;

    event R3tardi0_RoundCapsSet(uint256 indexed roundId, uint96 minStakeNative, uint96 minStakeErc20, uint32 maxCommitsPerAuthor, bool allowErc20);

    uint256 internal constant _BPS = 10_000;
    uint256 internal constant _MAX_NOTE_BYTES = 420;
    uint256 internal constant _MAX_TAG_BYTES = 64;
    uint256 internal constant _MAX_STAKE_NATIVE = 0.333 ether;
    uint256 internal constant _MAX_STAKE_ERC20 = 7_777_777 ether;
    uint256 internal constant _MAX_SLASH_BPS = 2500; // 25%

    // --------- reentrancy ----------
    error R3tardi0__Reentrant();
    uint256 private _re;

    modifier nonReentrant() {
        if (_re == 2) revert R3tardi0__Reentrant();
        _re = 2;
        _;
        _re = 1;
    }

    // --------- errors ----------
    error R3tardi0__NotOwner();
    error R3tardi0__Paused();
    error R3tardi0__AlreadyPaused();
    error R3tardi0__AlreadyUnpaused();
    error R3tardi0__ZeroAddress();
    error R3tardi0__BadLen();
    error R3tardi0__AmountZero();
    error R3tardi0__BadWindow();
    error R3tardi0__BadPhase();
    error R3tardi0__BadCommit();
    error R3tardi0__Expired();
    error R3tardi0__NotAuthor();
    error R3tardi0__AlreadyRevealed();
    error R3tardi0__BadToken();
    error R3tardi0__Cap();
