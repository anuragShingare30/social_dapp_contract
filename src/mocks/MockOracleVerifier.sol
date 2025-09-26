// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MockOracleVerifier {
    bool public verificationResult = true;
    
    function setVerificationResult(bool result) external {
        verificationResult = result;
    }
    
    function verifyProof(bytes calldata /* proof */, bytes calldata /* context */) external view returns (bool) {
        return verificationResult;
    }
}