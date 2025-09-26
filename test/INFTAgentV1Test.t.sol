// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/INFTAgentV1.sol";
import "../src/mocks/MockOracleVerifier.sol";

contract INFTAgentV1Test is Test {
    SocialINFTAgent public agent;
    MockOracleVerifier public oracle;

    address public owner = address(0xABCD);
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);
    address public user3 = address(0x3333);
    address public agentAddress = address(0x4444);

    uint256 public constant MINT_PRICE = 0.001 ether;

    // Test data
    string constant TOKEN_URI = "ipfs://QmTestTokenURI";
    bytes32 constant METADATA_HASH = keccak256("test metadata");
    string constant AGENT_DID = "did:agent:test123";
    string constant MEMORY_ROOT = "QmTestMemoryRoot";
    string constant ENCRYPTED_URI = "encrypted://test";
    string constant AGENT_TYPE = "assistant";

    event MetadataUpdated(uint256 indexed tokenId, bytes32 metadataHash);
    event EncryptedURIUpdated(uint256 indexed tokenId, string encryptedURI);
    event AgentDIDUpdated(uint256 indexed tokenId, string agentDID);
    event MemoryRootUpdated(uint256 indexed tokenId, string memoryRoot);
    event PersonaLocked(uint256 indexed tokenId);
    event AgentAuthorized(uint256 indexed tokenId, address indexed agent, bytes permissions, uint256 expiresAt);
    event AgentRevoked(uint256 indexed tokenId, address indexed agent);
    event AgentFollowed(uint256 indexed followerTokenId, uint256 indexed targetTokenId);
    event AgentUnfollowed(uint256 indexed followerTokenId, uint256 indexed targetTokenId);
    event AgentInteraction(uint256 indexed agentA, uint256 indexed agentB, bytes32 interactionHash, string interactionType);
    event ReputationUpdated(uint256 indexed tokenId, uint256 newTrustScore);
    event CollaborationStarted(uint256 indexed agentA, uint256 indexed agentB, bytes32 collaborationId);
    event CollaborationCompleted(uint256 indexed agentA, uint256 indexed agentB, bytes32 collaborationId, bool successful);

    function setUp() public {
        vm.startPrank(owner);
        oracle = new MockOracleVerifier();
        agent = new SocialINFTAgent("SocialAgent", "SA", address(oracle));
        vm.stopPrank();

        // Fund test addresses
        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
        vm.deal(user3, 10 ether);
    }

    /* ========== DEPLOYMENT TESTS ========== */

    function testDeployment() public {
        assertEq(agent.name(), "SocialAgent");
        assertEq(agent.symbol(), "SA");
        assertEq(agent.owner(), owner);
        assertEq(agent.oracleVerifier(), address(oracle));
        assertEq(agent.mintPrice(), MINT_PRICE);
        assertTrue(agent.publicMintEnabled());
    }

    function testDeploymentWithZeroOracle() public {
        vm.expectRevert("zero oracle");
        new SocialINFTAgent("Test", "T", address(0));
    }

    /* ========== MINTING TESTS ========== */

    function testMintByOwner() public {
        vm.startPrank(owner);
        
        vm.expectEmit(true, false, false, true);
        emit MetadataUpdated(1, METADATA_HASH);
        
        uint256 tokenId = agent.mint(
            user1,
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );

        assertEq(tokenId, 1);
        assertEq(agent.ownerOf(tokenId), user1);
        assertEq(agent.tokenURI(tokenId), TOKEN_URI);
        assertEq(agent.getMetadataHash(tokenId), METADATA_HASH);
        assertEq(agent.getAgentDID(tokenId), AGENT_DID);
        assertEq(agent.getMemoryRoot(tokenId), MEMORY_ROOT);
        assertEq(agent.getEncryptedURI(tokenId), ENCRYPTED_URI);
        assertEq(agent.getAgentType(tokenId), AGENT_TYPE);
        assertFalse(agent.isPersonaLocked(tokenId));

        // Check reputation initialization
        (,,, uint256 trustScore) = agent.getAgentReputation(tokenId);
        assertEq(trustScore, 500);

        vm.stopPrank();
    }

    function testPublicMint() public {
        vm.startPrank(user1);
        
        uint256 tokenId = agent.mint{value: MINT_PRICE}(
            user1,
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );

        assertEq(tokenId, 1);
        assertEq(agent.ownerOf(tokenId), user1);
        
        vm.stopPrank();
    }

    function testMintInsufficientPayment() public {
        vm.startPrank(user1);
        
        vm.expectRevert("not authorized to mint");
        agent.mint{value: MINT_PRICE - 1}(
            user1,
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );
        
        vm.stopPrank();
    }

    function testMintToZeroAddress() public {
        vm.startPrank(owner);
        
        vm.expectRevert("mint to zero");
        agent.mint(
            address(0),
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );
        
        vm.stopPrank();
    }

    function testAuthorizedMinter() public {
        vm.prank(owner);
        agent.setAuthorizedMinter(user1, true);

        vm.startPrank(user1);
        uint256 tokenId = agent.mint(
            user1,
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );
        assertEq(tokenId, 1);
        vm.stopPrank();
    }

    /* ========== METADATA UPDATE TESTS ========== */

    function testUpdateMetadata() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user1);
        
        string memory newEncryptedURI = "new_encrypted_uri";
        vm.expectEmit(true, false, false, true);
        emit EncryptedURIUpdated(tokenId, newEncryptedURI);
        agent.updateEncryptedURI(tokenId, newEncryptedURI);
        assertEq(agent.getEncryptedURI(tokenId), newEncryptedURI);

        bytes32 newMetadataHash = keccak256("new metadata");
        agent.updateMetadataHash(tokenId, newMetadataHash);
        assertEq(agent.getMetadataHash(tokenId), newMetadataHash);

        string memory newAgentDID = "did:agent:new";
        agent.updateAgentDID(tokenId, newAgentDID);
        assertEq(agent.getAgentDID(tokenId), newAgentDID);

        string memory newMemoryRoot = "new_memory_root";
        agent.updateMemoryRoot(tokenId, newMemoryRoot);
        assertEq(agent.getMemoryRoot(tokenId), newMemoryRoot);
        
        vm.stopPrank();
    }

    function testUpdateMetadataNotOwner() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user2);
        vm.expectRevert(abi.encodeWithSelector(SocialINFTAgent.NotTokenOwner.selector));
        agent.updateEncryptedURI(tokenId, "new_uri");
        vm.stopPrank();
    }

    function testLockPersona() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user1);
        vm.expectEmit(true, false, false, false);
        emit PersonaLocked(tokenId);
        agent.lockPersona(tokenId);
        assertTrue(agent.isPersonaLocked(tokenId));
        vm.stopPrank();
    }

    /* ========== AGENT AUTHORIZATION TESTS ========== */

    function testAuthorizeAgent() public {
        uint256 tokenId = _mintToken(user1);
        bytes memory permissions = "read,write";
        uint256 expiresAt = block.timestamp + 1000;
        
        vm.startPrank(user1);
        vm.expectEmit(true, true, false, true);
        emit AgentAuthorized(tokenId, agentAddress, permissions, expiresAt);
        
        agent.authorizeAgent(tokenId, agentAddress, permissions, expiresAt, true, true, false);
        
        assertTrue(agent.isAgentAuthorized(tokenId, agentAddress));
        vm.stopPrank();
    }

    function testRevokeAgent() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user1);
        agent.authorizeAgent(tokenId, agentAddress, "permissions", 0, true, true, false);
        assertTrue(agent.isAgentAuthorized(tokenId, agentAddress));
        
        vm.expectEmit(true, true, false, false);
        emit AgentRevoked(tokenId, agentAddress);
        agent.revokeAgent(tokenId, agentAddress);
        
        assertFalse(agent.isAgentAuthorized(tokenId, agentAddress));
        vm.stopPrank();
    }

    function testAuthorizeAgentZeroAddress() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user1);
        vm.expectRevert("agent zero");
        agent.authorizeAgent(tokenId, address(0), "permissions", 0, true, true, false);
        vm.stopPrank();
    }

    function testExpiredAuthorization() public {
        uint256 tokenId = _mintToken(user1);
        uint256 expiresAt = block.timestamp + 100;
        
        vm.startPrank(user1);
        agent.authorizeAgent(tokenId, agentAddress, "permissions", expiresAt, true, true, false);
        assertTrue(agent.isAgentAuthorized(tokenId, agentAddress));
        
        // Fast forward time
        vm.warp(block.timestamp + 200);
        assertFalse(agent.isAgentAuthorized(tokenId, agentAddress));
        vm.stopPrank();
    }

    /* ========== SOCIAL INTERACTION TESTS ========== */

    function testFollowAgent() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        vm.expectEmit(true, true, false, false);
        emit AgentFollowed(tokenId1, tokenId2);
        
        agent.followAgent(tokenId1, tokenId2);
        
        (bool isFollowing,,,) = agent.getSocialConnection(tokenId1, tokenId2);
        assertTrue(isFollowing);
        
        uint256[] memory followers = agent.getAgentFollowers(tokenId2);
        assertEq(followers.length, 1);
        assertEq(followers[0], tokenId1);
        
        uint256[] memory following = agent.getAgentFollowing(tokenId1);
        assertEq(following.length, 1);
        assertEq(following[0], tokenId2);
        vm.stopPrank();
    }

    function testUnfollowAgent() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        agent.followAgent(tokenId1, tokenId2);
        
        vm.expectEmit(true, true, false, false);
        emit AgentUnfollowed(tokenId1, tokenId2);
        agent.unfollowAgent(tokenId1, tokenId2);
        
        (bool isFollowing,,,) = agent.getSocialConnection(tokenId1, tokenId2);
        assertFalse(isFollowing);
        vm.stopPrank();
    }

    function testCannotFollowSelf() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user1);
        vm.expectRevert("cannot follow self");
        agent.followAgent(tokenId, tokenId);
        vm.stopPrank();
    }

    function testCannotFollowTwice() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        agent.followAgent(tokenId1, tokenId2);
        
        vm.expectRevert("already following");
        agent.followAgent(tokenId1, tokenId2);
        vm.stopPrank();
    }

    function testRecordInteraction() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        agent.recordInteraction(tokenId1, tokenId2, "message", "hello");
        
        (uint256 totalInteractions1,,,) = agent.getAgentReputation(tokenId1);
        (uint256 totalInteractions2,,,) = agent.getAgentReputation(tokenId2);
        
        assertEq(totalInteractions1, 1);
        assertEq(totalInteractions2, 1);
        
        bytes32[] memory history1 = agent.getInteractionHistory(tokenId1);
        bytes32[] memory history2 = agent.getInteractionHistory(tokenId2);
        
        assertEq(history1.length, 1);
        assertEq(history2.length, 1);
        assertEq(history1[0], history2[0]);
        vm.stopPrank();
    }

    function testRateAgent() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        agent.rateAgent(tokenId1, tokenId2, true);
        
        (,uint256 positiveRatings,,) = agent.getAgentReputation(tokenId2);
        assertEq(positiveRatings, 1);
        
        (,, uint256 reputationScore,) = agent.getSocialConnection(tokenId1, tokenId2);
        assertEq(reputationScore, 10);
        vm.stopPrank();
    }

    function testCannotRateSelf() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(user1);
        vm.expectRevert("cannot rate self");
        agent.rateAgent(tokenId, tokenId, true);
        vm.stopPrank();
    }

    function testStartCollaboration() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        agent.startCollaboration(tokenId1, tokenId2);
        
        (, bool isCollaborating,,) = agent.getSocialConnection(tokenId1, tokenId2);
        assertTrue(isCollaborating);
        
        (, bool isCollaborating2,,) = agent.getSocialConnection(tokenId2, tokenId1);
        assertTrue(isCollaborating2);
        vm.stopPrank();
    }

    function testCompleteCollaboration() public {
        uint256 tokenId1 = _mintToken(user1);
        uint256 tokenId2 = _mintToken(user2);
        
        vm.startPrank(user1);
        agent.startCollaboration(tokenId1, tokenId2);
        agent.completeCollaboration(tokenId1, tokenId2, true);
        
        (, bool isCollaborating,,) = agent.getSocialConnection(tokenId1, tokenId2);
        assertFalse(isCollaborating);
        
        (,, uint256 collaborationCount1,) = agent.getAgentReputation(tokenId1);
        (,, uint256 collaborationCount2,) = agent.getAgentReputation(tokenId2);
        
        assertEq(collaborationCount1, 1);
        assertEq(collaborationCount2, 1);
        vm.stopPrank();
    }

    /* ========== ADMIN TESTS ========== */

    function testSetMintPrice() public {
        vm.startPrank(owner);
        uint256 newPrice = 0.002 ether;
        agent.setMintPrice(newPrice);
        assertEq(agent.mintPrice(), newPrice);
        vm.stopPrank();
    }

    function testSetPublicMintEnabled() public {
        vm.startPrank(owner);
        agent.setPublicMintEnabled(false);
        assertFalse(agent.publicMintEnabled());
        vm.stopPrank();
    }

    function testWithdrawFees() public {
        // Mint with payment to generate fees
        vm.startPrank(user1);
        agent.mint{value: MINT_PRICE}(
            user1,
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );
        vm.stopPrank();
        
        uint256 contractBalance = address(agent).balance;
        assertEq(contractBalance, MINT_PRICE);
        
        uint256 ownerBalanceBefore = owner.balance;
        
        vm.prank(owner);
        agent.withdrawFees();
        
        assertEq(address(agent).balance, 0);
        assertEq(owner.balance, ownerBalanceBefore + MINT_PRICE);
    }

    function testSetOracleVerifier() public {
        MockOracleVerifier newOracle = new MockOracleVerifier();
        
        vm.startPrank(owner);
        agent.setOracleVerifier(address(newOracle));
        assertEq(agent.oracleVerifier(), address(newOracle));
        vm.stopPrank();
    }

    function testSetOracleVerifierZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert("zero address");
        agent.setOracleVerifier(address(0));
        vm.stopPrank();
    }

    /* ========== BURN TESTS ========== */

    function testBurn() public {
        uint256 tokenId = _mintToken(user1);
        
        vm.startPrank(owner);
        agent.burn(tokenId);
        
        // After burning, ownerOf should revert with ERC721NonexistentToken
        vm.expectRevert(abi.encodeWithSignature("ERC721NonexistentToken(uint256)", tokenId));
        agent.ownerOf(tokenId);
        vm.stopPrank();
    }

    function testBurnNonExistentToken() public {
        vm.startPrank(owner);
        vm.expectRevert("not exist");
        agent.burn(999);
        vm.stopPrank();
    }

    /* ========== ORACLE TRANSFER TESTS ========== */

    function testTransferWithOracleProof() public {
        uint256 tokenId = _mintToken(user1);
        
        oracle.setVerificationResult(true);
        
        vm.startPrank(user1);
        agent.transferWithOracleProof(
            user1,
            user2,
            tokenId,
            "sealedKey",
            "proof",
            "context"
        );
        
        assertEq(agent.ownerOf(tokenId), user2);
        vm.stopPrank();
    }

    function testTransferWithOracleProofFailed() public {
        uint256 tokenId = _mintToken(user1);
        
        oracle.setVerificationResult(false);
        
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(SocialINFTAgent.OracleVerificationFailed.selector));
        agent.transferWithOracleProof(
            user1,
            user2,
            tokenId,
            "sealedKey",
            "proof",
            "context"
        );
        vm.stopPrank();
    }

    /* ========== HELPER FUNCTIONS ========== */

    function _mintToken(address to) internal returns (uint256) {
        vm.prank(owner);
        return agent.mint(
            to,
            TOKEN_URI,
            METADATA_HASH,
            AGENT_DID,
            MEMORY_ROOT,
            ENCRYPTED_URI,
            AGENT_TYPE
        );
    }

    /* ========== FUZZ TESTS ========== */

    function testFuzzMint(address to, string calldata uri, bytes32 hash) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0); // Assume EOA to avoid ERC721InvalidReceiver
        vm.assume(uint160(to) > 0x100); // Avoid precompiles and low addresses
        
        vm.startPrank(owner);
        uint256 tokenId = agent.mint(to, uri, hash, AGENT_DID, MEMORY_ROOT, ENCRYPTED_URI, AGENT_TYPE);
        
        assertEq(agent.ownerOf(tokenId), to);
        assertEq(agent.getMetadataHash(tokenId), hash);
        assertEq(agent.tokenURI(tokenId), uri);
        vm.stopPrank();
    }

    function testFuzzFollowUnfollow(uint8 numAgents) public {
        vm.assume(numAgents >= 2 && numAgents <= 10);
        
        uint256[] memory tokenIds = new uint256[](numAgents);
        
        // Mint tokens
        vm.startPrank(owner);
        for (uint8 i = 0; i < numAgents; i++) {
            address user = address(uint160(0x1000 + i));
            tokenIds[i] = agent.mint(
                user,
                TOKEN_URI,
                METADATA_HASH,
                AGENT_DID,
                MEMORY_ROOT,
                ENCRYPTED_URI,
                AGENT_TYPE
            );
        }
        vm.stopPrank();
        
        // Test following
        address firstUser = address(uint160(0x1000));
        vm.startPrank(firstUser);
        
        for (uint8 i = 1; i < numAgents; i++) {
            agent.followAgent(tokenIds[0], tokenIds[i]);
            (bool isFollowing,,,) = agent.getSocialConnection(tokenIds[0], tokenIds[i]);
            assertTrue(isFollowing);
        }
        
        uint256[] memory following = agent.getAgentFollowing(tokenIds[0]);
        assertEq(following.length, numAgents - 1);
        
        vm.stopPrank();
    }
}
