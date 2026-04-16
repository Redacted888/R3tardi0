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
    error R3tardi0__NativeRejected();
    error R3tardi0__BadCall();

    // --------- events ----------
    event R3tardi0_OwnerShift(address indexed prev, address indexed next);
    event R3tardi0_PauseChanged(bool paused, address indexed by);
    event R3tardi0_FeeSet(uint256 bps);
    event R3tardi0_FeeSinkSet(address indexed prev, address indexed next);
    event R3tardi0_RoundOpened(uint256 indexed roundId, uint64 commitUntil, uint64 revealUntil);
    event R3tardi0_Committed(uint256 indexed roundId, address indexed author, bytes32 indexed commitHash, uint256 stakeNative);
    event R3tardi0_Revealed(
        uint256 indexed roundId,
        address indexed author,
        bytes32 indexed commitHash,
        bytes32 payloadHash,
        uint256 feeNative,
        uint256 stakeRefund
    );
    event R3tardi0_CommittedERC20(uint256 indexed roundId, address indexed token, address indexed author, bytes32 commitHash, uint256 stake);
    event R3tardi0_RevealedERC20(uint256 indexed roundId, address indexed token, address indexed author, bytes32 commitHash, bytes32 payloadHash, uint256 fee, uint256 refund);
    event R3tardi0_ExpiredClaimed(uint256 indexed roundId, address indexed author, bytes32 indexed commitHash, uint256 slash, uint256 payout);
    event R3tardi0_ExpiredClaimedERC20(uint256 indexed roundId, address indexed token, address indexed author, bytes32 commitHash, uint256 slash, uint256 payout);
    event R3tardi0_SlashSet(uint256 bps);
    event R3tardi0_TokenAllowSet(address indexed token, bool allowed);
    event R3tardi0_Notice(bytes32 indexed tag, uint256 a, uint256 b, address indexed who);

    // --------- state ----------
    address private _owner;
    bool public paused;

    uint256 public feeBps;
    address public feeSink;
    uint256 public unrevealedSlashBps;
    mapping(address => bool) public allowedToken;

    H0piuM public immutable VAULT;

    struct Round {
        uint64 commitUntil;
        uint64 revealUntil;
        bool exists;
    }

    struct Commitment {
        address author;
        uint96 stakeNative;
        bool revealed;
        uint64 committedAt;
        bytes32 payloadHash; // set at reveal
    }

    // roundId => commitHash => commitment
    mapping(uint256 => mapping(bytes32 => Commitment)) public commitments;
    mapping(uint256 => Round) public rounds;
    uint256 public roundsCount;

    // ERC20 stakes tracked separately: roundId => token => commitHash => stake amount
    mapping(uint256 => mapping(address => mapping(bytes32 => uint256))) public erc20Stake;
    mapping(uint256 => mapping(bytes32 => address)) public commitToken;

    modifier onlyOwner() {
        if (msg.sender != _owner) revert R3tardi0__NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert R3tardi0__Paused();
        _;
    }

    constructor() {
        _owner = msg.sender;
        paused = false;
        _re = 1;

        // Fee defaults: 69 bps to a deterministic pseudo-random sink (changeable by owner).
        // No external addresses required at deploy.
        feeBps = 69;
        feeSink = _randomSink();
        unrevealedSlashBps = 333; // 3.33%

        VAULT = new H0piuM();
        emit R3tardi0_OwnerShift(address(0), msg.sender);
        emit R3tardi0_FeeSet(feeBps);
        emit R3tardi0_FeeSinkSet(address(0), feeSink);
        emit R3tardi0_SlashSet(unrevealedSlashBps);
    }

    receive() external payable {
        revert R3tardi0__NativeRejected();
    }

    // --------- admin ----------
    function owner() external view returns (address) {
        return _owner;
    }

    function transferOwner(address next) external onlyOwner {
        if (next == address(0)) revert R3tardi0__ZeroAddress();
        address prev = _owner;
        _owner = next;
        emit R3tardi0_OwnerShift(prev, next);
    }

    function pause() external onlyOwner {
        if (paused) revert R3tardi0__AlreadyPaused();
        paused = true;
        emit R3tardi0_PauseChanged(true, msg.sender);
    }

    function unpause() external onlyOwner {
        if (!paused) revert R3tardi0__AlreadyUnpaused();
        paused = false;
        emit R3tardi0_PauseChanged(false, msg.sender);
    }

    function setFeeBps(uint256 bps) external onlyOwner {
        if (bps > 500) revert R3tardi0__Cap(); // hard cap: 5%
        feeBps = bps;
        emit R3tardi0_FeeSet(bps);
    }

    function setUnrevealedSlashBps(uint256 bps) external onlyOwner {
        if (bps > _MAX_SLASH_BPS) revert R3tardi0__Cap();
        unrevealedSlashBps = bps;
        emit R3tardi0_SlashSet(bps);
    }

    function setAllowedToken(address token, bool allowed) external onlyOwner {
        if (token == address(0)) revert R3tardi0__ZeroAddress();
        allowedToken[token] = allowed;
        emit R3tardi0_TokenAllowSet(token, allowed);
    }

    function setFeeSink(address next) external onlyOwner {
        if (next == address(0)) revert R3tardi0__ZeroAddress();
        address prev = feeSink;
        feeSink = next;
        emit R3tardi0_FeeSinkSet(prev, next);
    }

    // --------- rounds ----------
    function openRound(uint64 commitSeconds, uint64 revealSeconds) external onlyOwner whenNotPaused returns (uint256 roundId) {
        if (commitSeconds < 5 minutes || commitSeconds > 9 days) revert R3tardi0__BadWindow();
        if (revealSeconds < 5 minutes || revealSeconds > 11 days) revert R3tardi0__BadWindow();
        roundId = ++roundsCount;
        uint64 commitUntil = uint64(block.timestamp) + commitSeconds;
        uint64 revealUntil = commitUntil + revealSeconds;
        rounds[roundId] = Round({commitUntil: commitUntil, revealUntil: revealUntil, exists: true});
        emit R3tardi0_RoundOpened(roundId, commitUntil, revealUntil);
    }

    function setRoundCaps(
        uint256 roundId,
        uint96 minStakeNative,
        uint96 minStakeErc20,
        uint32 maxCommitsPerAuthor,
        bool allowErc20
    ) external onlyOwner {
        Round memory r = rounds[roundId];
        if (!r.exists) revert R3tardi0__BadPhase();
        if (minStakeNative > _MAX_STAKE_NATIVE) revert R3tardi0__Cap();
        if (minStakeErc20 > _MAX_STAKE_ERC20) revert R3tardi0__Cap();
        if (maxCommitsPerAuthor == 0 || maxCommitsPerAuthor > 50_000) revert R3tardi0__Cap();
        roundCaps[roundId] = RoundCaps({
            minStakeNative: minStakeNative,
            minStakeErc20: minStakeErc20,
            maxCommitsPerAuthor: maxCommitsPerAuthor,
            allowErc20: allowErc20
        });
        emit R3tardi0_RoundCapsSet(roundId, minStakeNative, minStakeErc20, maxCommitsPerAuthor, allowErc20);
    }

    function roundPhase(uint256 roundId) external view returns (uint8 phase, uint64 commitUntil, uint64 revealUntil) {
        Round memory r = rounds[roundId];
        if (!r.exists) return (0, 0, 0);
        commitUntil = r.commitUntil;
        revealUntil = r.revealUntil;
        if (block.timestamp <= commitUntil) return (1, commitUntil, revealUntil); // commit
        if (block.timestamp <= revealUntil) return (2, commitUntil, revealUntil); // reveal
        return (3, commitUntil, revealUntil); // ended
    }

    // --------- commits (native stake) ----------
    // commitHash := keccak256(abi.encodePacked(author, roundId, salt, noteBytes, tagBytes))

    function computeCommitHash(
        address author,
        uint256 roundId,
        bytes32 salt,
        bytes calldata note,
        bytes calldata tag
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(author, roundId, salt, note, tag));
    }

    function computePayloadHashNative(bytes calldata note, bytes calldata tag, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(note, tag, salt, _APP_FINGERPRINT, _RULESET_HASH));
    }

    function computePayloadHashERC20(bytes calldata note, bytes calldata tag, bytes32 salt, address token)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(note, tag, salt, token, _APP_FINGERPRINT));
    }

    function limits()
        external
        pure
        returns (
            uint256 maxNoteBytes,
            uint256 maxTagBytes,
            uint256 maxStakeNative,
            uint256 maxStakeErc20,
            uint256 maxSlashBps,
            uint256 pageMax
        )
    {
        maxNoteBytes = _MAX_NOTE_BYTES;
        maxTagBytes = _MAX_TAG_BYTES;
        maxStakeNative = _MAX_STAKE_NATIVE;
        maxStakeErc20 = _MAX_STAKE_ERC20;
        maxSlashBps = _MAX_SLASH_BPS;
        pageMax = _PAGE_MAX;
    }

    function commitExists(uint256 roundId, bytes32 commitHash) external view returns (bool) {
        return commitments[roundId][commitHash].author != address(0);
    }

    function commitRevealed(uint256 roundId, bytes32 commitHash) external view returns (bool) {
        Commitment memory c = commitments[roundId][commitHash];
        if (c.author == address(0)) return false;
        return c.revealed;
    }

    function roundExists(uint256 roundId) external view returns (bool) {
        return rounds[roundId].exists;
    }

    function timeLeft(uint256 roundId) external view returns (uint256 commitLeft, uint256 revealLeft) {
        Round memory r = rounds[roundId];
        if (!r.exists) return (0, 0);
        if (block.timestamp < r.commitUntil) commitLeft = r.commitUntil - uint64(block.timestamp);
        if (block.timestamp < r.revealUntil) revealLeft = r.revealUntil - uint64(block.timestamp);
    }

    function computeCommitHashFromHashes(
        address author,
        uint256 roundId,
        bytes32 salt,
        bytes32 noteHash,
        bytes32 tagHash
    ) external pure returns (bytes32) {
        // Useful for front-ends: hash large blobs off-chain, keep calldata small.
        return keccak256(abi.encodePacked(author, roundId, salt, noteHash, tagHash));
    }

    function computePayloadHashNativeFromHashes(bytes32 noteHash, bytes32 tagHash, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(noteHash, tagHash, salt, _APP_FINGERPRINT, _RULESET_HASH));
    }

    function computePayloadHashERC20FromHashes(bytes32 noteHash, bytes32 tagHash, bytes32 salt, address token)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(noteHash, tagHash, salt, token, _APP_FINGERPRINT));
    }

    function commit(uint256 roundId, bytes32 commitHash) external payable whenNotPaused nonReentrant {
        _commitNative(msg.sender, roundId, commitHash, msg.value);
    }

    function commitFor(address author, uint256 roundId, bytes32 commitHash) external payable whenNotPaused nonReentrant {
        if (author == address(0)) revert R3tardi0__ZeroAddress();
        _commitNative(author, roundId, commitHash, msg.value);
    }

    function _commitNative(address author, uint256 roundId, bytes32 commitHash, uint256 stakeNative) internal {
        Round memory r = rounds[roundId];
        if (!r.exists) revert R3tardi0__BadPhase();
        if (block.timestamp > r.commitUntil) revert R3tardi0__Expired();
        if (commitHash == bytes32(0)) revert R3tardi0__BadCommit();
        if (stakeNative == 0) revert R3tardi0__AmountZero();
        if (stakeNative > _MAX_STAKE_NATIVE) revert R3tardi0__Cap();

        RoundCaps memory caps = roundCaps[roundId];
        if (caps.maxCommitsPerAuthor != 0) {
            uint32 used = roundAuthorCommitCount32[roundId][author];
            if (used >= caps.maxCommitsPerAuthor) revert R3tardi0__Cap();
            roundAuthorCommitCount32[roundId][author] = used + 1;
        }
        if (caps.minStakeNative != 0 && stakeNative < uint256(caps.minStakeNative)) revert R3tardi0__Cap();

        Commitment storage c = commitments[roundId][commitHash];
        if (c.author != address(0)) revert R3tardi0__BadCommit();
        c.author = author;
        c.stakeNative = uint96(stakeNative);
        c.revealed = false;
        c.committedAt = uint64(block.timestamp);
        emit R3tardi0_Committed(roundId, author, commitHash, stakeNative);

        _roundCommits[roundId].push(commitHash);
        _authorCommits[author].push(commitHash);
        _roundAuthorCommits[roundId][author].push(commitHash);
        roundTally[roundId].commitCount += 1;
        roundTally[roundId].totalNativeStaked += uint128(stakeNative);

        // stake is held in the vault under this contract's balance key
        VAULT.depositNative{value: stakeNative}(address(this));
    }

    function reveal(
        uint256 roundId,
        bytes32 salt,
        bytes calldata note,
        bytes calldata tag
    ) external whenNotPaused nonReentrant {
        Round memory r = rounds[roundId];
        if (!r.exists) revert R3tardi0__BadPhase();
        if (block.timestamp <= r.commitUntil) revert R3tardi0__BadPhase();
        if (block.timestamp > r.revealUntil) revert R3tardi0__Expired();
        if (note.length == 0 || note.length > _MAX_NOTE_BYTES) revert R3tardi0__BadLen();
        if (tag.length == 0 || tag.length > _MAX_TAG_BYTES) revert R3tardi0__BadLen();

        bytes32 commitHash = keccak256(abi.encodePacked(msg.sender, roundId, salt, note, tag));
        Commitment storage c = commitments[roundId][commitHash];
        if (c.author == address(0)) revert R3tardi0__BadCommit();
        if (c.author != msg.sender) revert R3tardi0__NotAuthor();
        if (c.revealed) revert R3tardi0__AlreadyRevealed();

        c.revealed = true;
        bytes32 payloadHash = keccak256(abi.encodePacked(note, tag, salt, _APP_FINGERPRINT, _RULESET_HASH));
        c.payloadHash = payloadHash;

        uint256 stake = uint256(c.stakeNative);
        uint256 fee = (stake * feeBps) / _BPS;
        uint256 refund = stake - fee;

        // withdraw from vault to settle
        if (fee > 0) {
            VAULT.withdrawNative(payable(feeSink), fee);
        }
        if (refund > 0) {
            VAULT.withdrawNative(payable(msg.sender), refund);
        }

        emit R3tardi0_Revealed(roundId, msg.sender, commitHash, payloadHash, fee, refund);
        roundTally[roundId].revealCount += 1;
        roundTally[roundId].totalNativeFees += uint128(fee);
    }

    // Reveal relay is supported via `revealForWithSig` / `revealERC20ForWithSig` (author included in payload).

    function revealForWithSig(
        address author,
        uint256 roundId,
        bytes32 salt,
        bytes calldata note,
        bytes calldata tag,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused nonReentrant returns (uint256 nonce) {
        if (author == address(0)) revert R3tardi0__ZeroAddress();
        if (block.timestamp > deadline) revert R3tardi0__AuthExpired();
        if (note.length == 0 || note.length > _MAX_NOTE_BYTES) revert R3tardi0__BadLen();
        if (tag.length == 0 || tag.length > _MAX_TAG_BYTES) revert R3tardi0__BadLen();

        nonce = revealNonces[author];
        bytes32 noteHash = keccak256(note);
        bytes32 tagHash = keccak256(tag);
        bytes32 structHash = keccak256(
            abi.encode(_REVEAL_AUTH_TYPEHASH, author, roundId, salt, noteHash, tagHash, deadline, nonce)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = _recoverStrict(digest, v, r, s);
        if (signer != author) revert R3tardi0__AuthBadSig();
        revealNonces[author] = nonce + 1;

        Round memory rr = rounds[roundId];
        if (!rr.exists) revert R3tardi0__BadPhase();
        if (block.timestamp <= rr.commitUntil) revert R3tardi0__BadPhase();
        if (block.timestamp > rr.revealUntil) revert R3tardi0__Expired();

        bytes32 commitHash = keccak256(abi.encodePacked(author, roundId, salt, note, tag));
        Commitment storage c = commitments[roundId][commitHash];
        if (c.author == address(0)) revert R3tardi0__BadCommit();
        if (c.author != author) revert R3tardi0__NotAuthor();
        if (c.revealed) revert R3tardi0__AlreadyRevealed();

        c.revealed = true;
        bytes32 payloadHash = keccak256(abi.encodePacked(note, tag, salt, _APP_FINGERPRINT, _RULESET_HASH));
        c.payloadHash = payloadHash;

        uint256 stake = uint256(c.stakeNative);
        uint256 fee = (stake * feeBps) / _BPS;
        uint256 refund = stake - fee;
        if (fee > 0) VAULT.withdrawNative(payable(feeSink), fee);
        if (refund > 0) VAULT.withdrawNative(payable(author), refund);
        emit R3tardi0_Revealed(roundId, author, commitHash, payloadHash, fee, refund);
        emit R3tardi0_RevealRelayed(roundId, author, msg.sender, nonce);
        roundTally[roundId].revealCount += 1;
        roundTally[roundId].totalNativeFees += uint128(fee);
    }

    // --------- commits (ERC20 stake) ----------
    function commitERC20(uint256 roundId, address token, bytes32 commitHash, uint256 stake) external whenNotPaused nonReentrant {
        _commitErc20(msg.sender, roundId, token, commitHash, stake);
    }

    function commitERC20For(
        address author,
        uint256 roundId,
        address token,
        bytes32 commitHash,
        uint256 stake
    ) external whenNotPaused nonReentrant {
        if (author == address(0)) revert R3tardi0__ZeroAddress();
        _commitErc20(author, roundId, token, commitHash, stake);
    }

    function _commitErc20(address author, uint256 roundId, address token, bytes32 commitHash, uint256 stake) internal {
        Round memory r = rounds[roundId];
        if (!r.exists) revert R3tardi0__BadPhase();
        if (block.timestamp > r.commitUntil) revert R3tardi0__Expired();
        if (token == address(0)) revert R3tardi0__ZeroAddress();
        if (!allowedToken[token]) revert R3tardi0__BadToken();
        if (commitHash == bytes32(0)) revert R3tardi0__BadCommit();
        if (stake == 0) revert R3tardi0__AmountZero();
        if (stake > _MAX_STAKE_ERC20) revert R3tardi0__Cap();

        RoundCaps memory caps = roundCaps[roundId];
        if (!caps.allowErc20) revert R3tardi0__BadPhase();
        if (caps.maxCommitsPerAuthor != 0) {
            uint32 used = roundAuthorCommitCount32[roundId][author];
            if (used >= caps.maxCommitsPerAuthor) revert R3tardi0__Cap();
            roundAuthorCommitCount32[roundId][author] = used + 1;
        }
        if (caps.minStakeErc20 != 0 && stake < uint256(caps.minStakeErc20)) revert R3tardi0__Cap();

        Commitment storage c = commitments[roundId][commitHash];
        if (c.author != address(0)) revert R3tardi0__BadCommit();
        c.author = author;
        c.stakeNative = 0;
        c.revealed = false;
        c.committedAt = uint64(block.timestamp);

        token.safeTransferFrom(msg.sender, address(this), stake);
        token.safeApprove(address(VAULT), stake);
        VAULT.depositERC20(token, address(this), stake);

        commitToken[roundId][commitHash] = token;
        erc20Stake[roundId][token][commitHash] = stake;
        _roundCommits[roundId].push(commitHash);
        _authorCommits[author].push(commitHash);
        _roundAuthorCommits[roundId][author].push(commitHash);
        roundTally[roundId].commitCount += 1;
        roundTokenStaked[roundId][token] += stake;

        emit R3tardi0_CommittedERC20(roundId, token, author, commitHash, stake);
    }

    function revealERC20(
        uint256 roundId,
        address token,
        bytes32 salt,
        bytes calldata note,
        bytes calldata tag
    ) external whenNotPaused nonReentrant {
        Round memory r = rounds[roundId];
        if (!r.exists) revert R3tardi0__BadPhase();
        if (block.timestamp <= r.commitUntil) revert R3tardi0__BadPhase();
        if (block.timestamp > r.revealUntil) revert R3tardi0__Expired();
        if (token == address(0)) revert R3tardi0__ZeroAddress();
        if (note.length == 0 || note.length > _MAX_NOTE_BYTES) revert R3tardi0__BadLen();
        if (tag.length == 0 || tag.length > _MAX_TAG_BYTES) revert R3tardi0__BadLen();

        bytes32 commitHash = keccak256(abi.encodePacked(msg.sender, roundId, salt, note, tag));
        Commitment storage c = commitments[roundId][commitHash];
        if (c.author == address(0)) revert R3tardi0__BadCommit();
        if (c.author != msg.sender) revert R3tardi0__NotAuthor();
        if (c.revealed) revert R3tardi0__AlreadyRevealed();

        uint256 stake = erc20Stake[roundId][token][commitHash];
        if (stake == 0) revert R3tardi0__BadToken();

        c.revealed = true;
        bytes32 payloadHash = keccak256(abi.encodePacked(note, tag, salt, token, _APP_FINGERPRINT));
        c.payloadHash = payloadHash;

        uint256 fee = (stake * feeBps) / _BPS;
        uint256 refund = stake - fee;

        // Settle from the vault (staked into H0piuM under this contract's balance).
        if (fee > 0) VAULT.withdrawERC20(token, feeSink, fee);
        if (refund > 0) VAULT.withdrawERC20(token, msg.sender, refund);

        erc20Stake[roundId][token][commitHash] = 0;
        emit R3tardi0_RevealedERC20(roundId, token, msg.sender, commitHash, payloadHash, fee, refund);
        roundTokenFees[roundId][token] += fee;
    }

    function revealERC20ForWithSig(
        address author,
        uint256 roundId,
        address token,
        bytes32 salt,
        bytes calldata note,
        bytes calldata tag,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused nonReentrant returns (uint256 nonce) {
        if (author == address(0) || token == address(0)) revert R3tardi0__ZeroAddress();
        if (block.timestamp > deadline) revert R3tardi0__AuthExpired();
        if (note.length == 0 || note.length > _MAX_NOTE_BYTES) revert R3tardi0__BadLen();
        if (tag.length == 0 || tag.length > _MAX_TAG_BYTES) revert R3tardi0__BadLen();

        nonce = revealNonces[author];
        bytes32 noteHash = keccak256(note);
        bytes32 tagHash = keccak256(tag);
        bytes32 structHash = keccak256(
            abi.encode(_REVEAL_ERC20_AUTH_TYPEHASH, author, roundId, token, salt, noteHash, tagHash, deadline, nonce)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = _recoverStrict(digest, v, r, s);
        if (signer != author) revert R3tardi0__AuthBadSig();
        revealNonces[author] = nonce + 1;

        Round memory rr = rounds[roundId];
        if (!rr.exists) revert R3tardi0__BadPhase();
        if (block.timestamp <= rr.commitUntil) revert R3tardi0__BadPhase();
        if (block.timestamp > rr.revealUntil) revert R3tardi0__Expired();

        bytes32 commitHash = keccak256(abi.encodePacked(author, roundId, salt, note, tag));
        Commitment storage c = commitments[roundId][commitHash];
        if (c.author == address(0)) revert R3tardi0__BadCommit();
        if (c.author != author) revert R3tardi0__NotAuthor();
        if (c.revealed) revert R3tardi0__AlreadyRevealed();

        uint256 stake = erc20Stake[roundId][token][commitHash];
        if (stake == 0) revert R3tardi0__BadToken();

        c.revealed = true;
        bytes32 payloadHash = keccak256(abi.encodePacked(note, tag, salt, token, _APP_FINGERPRINT));
        c.payloadHash = payloadHash;

        uint256 fee = (stake * feeBps) / _BPS;
        uint256 refund = stake - fee;
        if (fee > 0) VAULT.withdrawERC20(token, feeSink, fee);
        if (refund > 0) VAULT.withdrawERC20(token, author, refund);

        erc20Stake[roundId][token][commitHash] = 0;
        emit R3tardi0_RevealedERC20(roundId, token, author, commitHash, payloadHash, fee, refund);
        emit R3tardi0_RevealRelayedERC20(roundId, token, author, msg.sender, nonce);
        roundTokenFees[roundId][token] += fee;
    }

    function claimExpired(uint256 roundId, bytes32 commitHash) external whenNotPaused nonReentrant {
        Round memory r = rounds[roundId];
        if (!r.exists) revert R3tardi0__BadPhase();
        if (block.timestamp <= r.revealUntil) revert R3tardi0__BadPhase();

        Commitment storage c = commitments[roundId][commitHash];
        if (c.author == address(0)) revert R3tardi0__BadCommit();
        if (c.author != msg.sender) revert R3tardi0__NotAuthor();
        if (c.revealed) revert R3tardi0__AlreadyRevealed();

        c.revealed = true; // lock it
        uint256 stakeNative = uint256(c.stakeNative);
        if (stakeNative > 0) {
            uint256 slash = (stakeNative * unrevealedSlashBps) / _BPS;
            uint256 payout = stakeNative - slash;
            if (slash > 0) VAULT.withdrawNative(payable(feeSink), slash);
            if (payout > 0) VAULT.withdrawNative(payable(msg.sender), payout);
            emit R3tardi0_ExpiredClaimed(roundId, msg.sender, commitHash, slash, payout);
            roundTally[roundId].totalNativeSlashed += uint128(slash);
            return;
        }

        address token = commitToken[roundId][commitHash];
        if (token == address(0)) revert R3tardi0__BadToken();
        uint256 stake = erc20Stake[roundId][token][commitHash];
        if (stake == 0) revert R3tardi0__BadToken();
        erc20Stake[roundId][token][commitHash] = 0;

        uint256 slashE = (stake * unrevealedSlashBps) / _BPS;
        uint256 payoutE = stake - slashE;
        if (slashE > 0) VAULT.withdrawERC20(token, feeSink, slashE);
        if (payoutE > 0) VAULT.withdrawERC20(token, msg.sender, payoutE);
        emit R3tardi0_ExpiredClaimedERC20(roundId, token, msg.sender, commitHash, slashE, payoutE);
        roundTokenSlashed[roundId][token] += slashE;
    }

    function batchClaimExpired(uint256 roundId, bytes32[] calldata commitHashes) external whenNotPaused nonReentrant {
        if (commitHashes.length > _PAGE_MAX) revert R3tardi0__Cap();
        for (uint256 i = 0; i < commitHashes.length; ) {
            claimExpired(roundId, commitHashes[i]);
            unchecked {
                ++i;
            }
        }
    }

    function batchRevealForWithSig(
        address author,
        uint256 roundId,
        bytes32[] calldata salts,
        bytes[] calldata notes,
        bytes[] calldata tags,
        uint256 deadline,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external whenNotPaused nonReentrant {
        uint256 n = salts.length;
        if (n == 0 || n > _PAGE_MAX) revert R3tardi0__Cap();
        if (notes.length != n || tags.length != n || vs.length != n || rs.length != n || ss.length != n) revert R3tardi0__BadLen();
        for (uint256 i = 0; i < n; ) {
            revealForWithSig(author, roundId, salts[i], notes[i], tags[i], deadline, vs[i], rs[i], ss[i]);
            unchecked {
                ++i;
            }
        }
    }

    function batchRevealERC20ForWithSig(
        address author,
        uint256 roundId,
        address token,
        bytes32[] calldata salts,
        bytes[] calldata notes,
        bytes[] calldata tags,
        uint256 deadline,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external whenNotPaused nonReentrant {
        uint256 n = salts.length;
        if (n == 0 || n > _PAGE_MAX) revert R3tardi0__Cap();
        if (notes.length != n || tags.length != n || vs.length != n || rs.length != n || ss.length != n) revert R3tardi0__BadLen();
        for (uint256 i = 0; i < n; ) {
            revealERC20ForWithSig(author, roundId, token, salts[i], notes[i], tags[i], deadline, vs[i], rs[i], ss[i]);
            unchecked {
                ++i;
            }
        }
    }

    function roundCommitCount(uint256 roundId) external view returns (uint256) {
        return _roundCommits[roundId].length;
    }

    function authorCommitCount(address author) external view returns (uint256) {
        return _authorCommits[author].length;
    }

    function roundCommitsPage(uint256 roundId, uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {
        if (limit > _PAGE_MAX) limit = _PAGE_MAX;
        bytes32[] storage src = _roundCommits[roundId];
        uint256 n = src.length;
        if (offset >= n) return new bytes32[](0);
        uint256 end = offset + limit;
        if (end > n) end = n;
        out = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; ) {
            out[i - offset] = src[i];
            unchecked {
                ++i;
            }
        }
    }

    function authorCommitsPage(address author, uint256 offset, uint256 limit) external view returns (bytes32[] memory out) {
        if (limit > _PAGE_MAX) limit = _PAGE_MAX;
        bytes32[] storage src = _authorCommits[author];
        uint256 n = src.length;
        if (offset >= n) return new bytes32[](0);
        uint256 end = offset + limit;
        if (end > n) end = n;
        out = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; ) {
            out[i - offset] = src[i];
            unchecked {
                ++i;
            }
        }
    }

    function roundAuthorCommitCount(uint256 roundId, address author) external view returns (uint256) {
        return _roundAuthorCommits[roundId][author].length;
    }

    function roundAuthorCommitsPage(uint256 roundId, address author, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory out)
    {
        if (limit > _PAGE_MAX) limit = _PAGE_MAX;
        bytes32[] storage src = _roundAuthorCommits[roundId][author];
        uint256 n = src.length;
        if (offset >= n) return new bytes32[](0);
        uint256 end = offset + limit;
        if (end > n) end = n;
        out = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; ) {
            out[i - offset] = src[i];
            unchecked {
                ++i;
            }
        }
    }

    function domainSeparatorV4() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function previewRevealDigest(
        address author,
        uint256 roundId,
        bytes32 salt,
        bytes32 noteHash,
        bytes32 tagHash,
        uint256 deadline,
        uint256 nonce
    ) external view returns (bytes32) {
        bytes32 sh = keccak256(abi.encode(_REVEAL_AUTH_TYPEHASH, author, roundId, salt, noteHash, tagHash, deadline, nonce));
        return _hashTypedDataV4(sh);
    }

    function previewRevealERC20Digest(
        address author,
        uint256 roundId,
        address token,
        bytes32 salt,
        bytes32 noteHash,
        bytes32 tagHash,
        uint256 deadline,
        uint256 nonce
    ) external view returns (bytes32) {
        bytes32 sh =
            keccak256(abi.encode(_REVEAL_ERC20_AUTH_TYPEHASH, author, roundId, token, salt, noteHash, tagHash, deadline, nonce));
        return _hashTypedDataV4(sh);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _EIP712_DOMAIN_TYPEHASH,
                    _EIP712_NAME_HASH,
                    _EIP712_VERSION_HASH,
                    block.chainid,
                    address(this)
                )
            );
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }

    function _recoverStrict(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        if (v != 27 && v != 28) revert R3tardi0__AuthBadSig();
        if (uint256(s) > _SECP256K1_HALF_ORDER) revert R3tardi0__AuthBadSig();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert R3tardi0__AuthBadSig();
        return signer;
    }

    // --------- convenience ----------
    function commitmentOf(uint256 roundId, bytes32 commitHash) external view returns (Commitment memory c) {
        c = commitments[roundId][commitHash];
    }

    struct CommitmentView {
        address author;
        bool revealed;
        uint64 committedAt;
        bytes32 payloadHash;
        uint256 stakeNative;
        address stakeToken;
        uint256 stakeErc20;
        uint8 phase; // 0 missing, 1 commit, 2 reveal, 3 ended
    }

    function commitmentView(uint256 roundId, bytes32 commitHash) external view returns (CommitmentView memory v) {
        Commitment memory c = commitments[roundId][commitHash];
        Round memory r = rounds[roundId];
        v.author = c.author;
        v.revealed = c.revealed;
        v.committedAt = c.committedAt;
        v.payloadHash = c.payloadHash;
        v.stakeNative = uint256(c.stakeNative);
