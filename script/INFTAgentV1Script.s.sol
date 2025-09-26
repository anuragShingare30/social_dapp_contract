// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/INFTAgentV1.sol";
import "../src/mocks/MockOracleVerifier.sol";

contract INFTAgentV1Script is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        // Deploy MockOracleVerifier
        MockOracleVerifier oracle = new MockOracleVerifier();
        console.log("MockOracleVerifier deployed at:", address(oracle));

        // Deploy SocialINFTAgent contract
        SocialINFTAgent agent = new SocialINFTAgent(
            "Social AI Agent NFT",
            "SAINFT",
            address(oracle)
        );
        console.log("SocialINFTAgent deployed at:", address(agent));
        console.log("Owner:", agent.owner());
        console.log("Mint Price:", agent.mintPrice());
        console.log("Public Mint Enabled:", agent.publicMintEnabled());

        vm.stopBroadcast();
    }
}
