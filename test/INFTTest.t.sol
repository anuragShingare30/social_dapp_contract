// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/INFTAgentV1.sol";
import "../src/mocks/MockOracleVerifier.sol";

contract INFTTest is Test {
    INFT public inft;
    MockOracleVerifier public oracle;

    address public owner = address(0xABCD);
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);
    address public executor = address(0x3333);

    // Test data
    string constant TOKEN_URI = "https://api.example.com/metadata/1";
    string constant ENCRYPTED_URI = "encrypted://QmTestURI";
    bytes32 constant METADATA_HASH = keccak256("test metadata with traits");

    event MetadataUpdated(uint256 indexed tokenId, bytes32 newHash);
    event UsageAuthorized(uint256 indexed tokenId, address indexed executor);
    event INFTMinted(uint256 indexed tokenId, address indexed to, bytes32 metadataHash);

    function setUp() public {
        vm.startPrank(owner);
        oracle = new MockOracleVerifier();
        inft = new INFT("Intelligent NFT", "INFT", address(oracle));
        vm.stopPrank();
    }

    /* ========== DEPLOYMENT TESTS ========== */

    function testDeployment() public view {
        assertEq(inft.name(), "Intelligent NFT");
        assertEq(inft.symbol(), "INFT");
        assertEq(inft.owner(), owner);
        assertEq(inft.oracle(), address(oracle));
        assertEq(inft.getNextTokenId(), 1);
        assertEq(inft.totalSupply(), 0);
    }

    function testDeploymentWithZeroOracle() public {
        vm.expectRevert("Oracle cannot be zero address");
        new INFT("Test", "TEST", address(0));
    }

    /* ========== MINTING TESTS ========== */

    function testMint() public {
        vm.expectEmit(true, true, false, true);
        emit INFTMinted(1, user1, METADATA_HASH);

        uint256 tokenId = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);

        assertEq(tokenId, 1);
        assertEq(inft.ownerOf(tokenId), user1);
        assertEq(inft.tokenURI(tokenId), TOKEN_URI);
        assertEq(inft.getEncryptedURI(tokenId), ENCRYPTED_URI);
        assertEq(inft.getMetadataHash(tokenId), METADATA_HASH);
        assertEq(inft.getNextTokenId(), 2);
        assertEq(inft.totalSupply(), 1);
    }

    function testMintToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(INFT.ZeroAddress.selector));
        inft.mint(address(0), TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);
    }

    function testMintMultipleTokens() public {
        uint256 tokenId1 = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);
        uint256 tokenId2 = inft.mint(user2, "uri2", "encrypted2", keccak256("metadata2"));

        assertEq(tokenId1, 1);
        assertEq(tokenId2, 2);
        assertEq(inft.totalSupply(), 2);
        assertEq(inft.getNextTokenId(), 3);
    }

    /* ========== AUTHORIZATION TESTS ========== */

    function testAuthorizeUsage() public {
        uint256 tokenId = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);
        bytes memory permissions = "read,write";

        vm.startPrank(user1);
        vm.expectEmit(true, true, false, false);
        emit UsageAuthorized(tokenId, executor);

        inft.authorizeUsage(tokenId, executor, permissions);

        assertTrue(inft.isAuthorized(tokenId, executor));
        assertEq(inft.getPermissions(tokenId, executor), permissions);
        vm.stopPrank();
    }

    function testAuthorizeUsageNotOwner() public {
        uint256 tokenId = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);

        vm.startPrank(user2);
        vm.expectRevert(abi.encodeWithSelector(INFT.NotTokenOwner.selector));
        inft.authorizeUsage(tokenId, executor, "permissions");
        vm.stopPrank();
    }

    function testGetPermissionsUnauthorized() public {
        uint256 tokenId = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);

        assertFalse(inft.isAuthorized(tokenId, executor));
        assertEq(inft.getPermissions(tokenId, executor), "");
    }

    /* ========== GETTER TESTS ========== */

    function testGetMetadataHashInvalidToken() public {
        vm.expectRevert(abi.encodeWithSelector(INFT.InvalidTokenId.selector));
        inft.getMetadataHash(999);
    }

    function testGetEncryptedURIInvalidToken() public {
        vm.expectRevert(abi.encodeWithSelector(INFT.InvalidTokenId.selector));
        inft.getEncryptedURI(999);
    }

    function testTokenURIInvalidToken() public {
        vm.expectRevert(abi.encodeWithSelector(INFT.InvalidTokenId.selector));
        inft.tokenURI(999);
    }

    /* ========== ADMIN TESTS ========== */

    function testSetOracle() public {
        MockOracleVerifier newOracle = new MockOracleVerifier();

        vm.startPrank(owner);
        inft.setOracle(address(newOracle));
        assertEq(inft.oracle(), address(newOracle));
        vm.stopPrank();
    }

    function testSetOracleZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert("Oracle cannot be zero address");
        inft.setOracle(address(0));
        vm.stopPrank();
    }

    function testSetOracleNotOwner() public {
        MockOracleVerifier newOracle = new MockOracleVerifier();

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user1));
        inft.setOracle(address(newOracle));
        vm.stopPrank();
    }

    /* ========== ORACLE VERIFICATION TESTS ========== */

    function testVerifyProof() public {
        oracle.setVerificationResult(true);
        assertTrue(inft.verifyProof("test proof"));

        oracle.setVerificationResult(false);
        assertFalse(inft.verifyProof("test proof"));
    }

    /* ========== INTEGRATION TESTS ========== */

    function testCompleteWorkflow() public {
        // Mint token
        uint256 tokenId = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);
        
        // Authorize executor
        vm.startPrank(user1);
        bytes memory permissions = "interact,read_traits";
        inft.authorizeUsage(tokenId, executor, permissions);
        vm.stopPrank();

        // Verify authorization
        assertTrue(inft.isAuthorized(tokenId, executor));
        assertEq(inft.getPermissions(tokenId, executor), permissions);

        // Verify metadata access
        assertEq(inft.getMetadataHash(tokenId), METADATA_HASH);
        assertEq(inft.getEncryptedURI(tokenId), ENCRYPTED_URI);
        assertEq(inft.tokenURI(tokenId), TOKEN_URI);
    }

    /* ========== FUZZ TESTS ========== */

    function testFuzzMint(address to, string calldata uri, bytes32 hash) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0); // Assume EOA
        vm.assume(uint160(to) > 0x100); // Avoid precompiles

        uint256 tokenId = inft.mint(to, uri, "encrypted", hash);

        assertEq(inft.ownerOf(tokenId), to);
        assertEq(inft.getMetadataHash(tokenId), hash);
        assertEq(inft.tokenURI(tokenId), uri);
    }

    function testFuzzAuthorization(address testExecutor, bytes calldata permissions) public {
        vm.assume(testExecutor != address(0));
        vm.assume(permissions.length > 0); // Ensure non-empty permissions
        
        uint256 tokenId = inft.mint(user1, TOKEN_URI, ENCRYPTED_URI, METADATA_HASH);

        vm.startPrank(user1);
        inft.authorizeUsage(tokenId, testExecutor, permissions);
        
        assertTrue(inft.isAuthorized(tokenId, testExecutor));
        assertEq(inft.getPermissions(tokenId, testExecutor), permissions);
        vm.stopPrank();
    }
}