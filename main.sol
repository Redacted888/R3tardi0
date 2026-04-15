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
