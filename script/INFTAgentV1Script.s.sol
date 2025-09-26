// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/INFTAgentV1.sol";
import "../src/mocks/MockOracleVerifier.sol";

contract INFTScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        // Deploy MockOracleVerifier
        MockOracleVerifier oracle = new MockOracleVerifier();
        console.log("MockOracleVerifier deployed at:", address(oracle));

        // Deploy INFT contract
        INFT inft = new INFT(
            "Intelligent NFT",
            "INFT",
            address(oracle)
        );
        console.log("INFT deployed at:", address(inft));
        console.log("Owner:", inft.owner());
        console.log("Oracle:", inft.oracle());
        console.log("Next Token ID:", inft.getNextTokenId());
        console.log("Total Supply:", inft.totalSupply());

        vm.stopBroadcast();
    }
}