// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// INFT.sol
/// - Intelligent NFT contract for AI agents
/// - Stores encrypted URI and metadata hash with traits schema
/// - Allows proper agent interaction through traits
/// - Simplified authorization system

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IOracle {
    /// verifyProof should validate cryptographic attestation
    /// and return true if the proof authorizes the requested operation.
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract INFT is ERC721, Ownable, ReentrancyGuard {

    /* ========== STATE VARIABLES ========== */
    // Core INFT data
    mapping(uint256 => bytes32) private _metadataHashes;
    mapping(uint256 => string) private _encryptedURIs;
    mapping(uint256 => string) private _tokenURIs;
    
    // Authorization mapping: tokenId => executor => permissions
    mapping(uint256 => mapping(address => bytes)) private _authorizations;
    
    // Oracle contract
    address public oracle;
    
    // Token ID counter starting from 1
    uint256 private _nextTokenId = 1;

    /* ========== EVENTS ========== */
    event MetadataUpdated(uint256 indexed tokenId, bytes32 newHash);
    event UsageAuthorized(uint256 indexed tokenId, address indexed executor);
    event INFTMinted(uint256 indexed tokenId, address indexed to, bytes32 metadataHash);

    /* ========== ERRORS ========== */
    error NotTokenOwner();
    error InvalidTokenId();
    error ZeroAddress();

    /* ========== CONSTRUCTOR ========== */
    constructor(
        string memory name,
        string memory symbol,
        address _oracle
    ) ERC721(name, symbol) Ownable(msg.sender) {
        require(_oracle != address(0), "Oracle cannot be zero address");
        oracle = _oracle;
    }

    /* ========== ADMIN FUNCTIONS ========== */

    function setOracle(address _oracle) external onlyOwner {
        require(_oracle != address(0), "Oracle cannot be zero address");
        oracle = _oracle;
    }

    /* ========== MINT FUNCTION ========== */

    /// @notice Mint a new iNFT with metadata containing traits schema
    /// @param to Address to mint the token to
    /// @param tokenURI_ Token URI containing traits and metadata
    /// @param encryptedURI Encrypted URI for off-chain data
    /// @param metadataHash Hash of the metadata for verification
    /// @return tokenId The minted token ID
    function mint(
        address to,
        string calldata tokenURI_,
        string calldata encryptedURI,
        bytes32 metadataHash
    ) external returns (uint256) {
        if (to == address(0)) revert ZeroAddress();
        
        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        
        _tokenURIs[tokenId] = tokenURI_;
        _encryptedURIs[tokenId] = encryptedURI;
        _metadataHashes[tokenId] = metadataHash;
        
        emit INFTMinted(tokenId, to, metadataHash);
        
        return tokenId;
    }

    /* ========== AUTHORIZATION ========== */

    /// @notice Authorize an address to use this token with specific permissions
    /// @param tokenId Token ID to authorize usage for
    /// @param executor Address to authorize
    /// @param permissions Permission bytes for the executor
    function authorizeUsage(
        uint256 tokenId,
        address executor,
        bytes calldata permissions
    ) external {
        if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner();
        _authorizations[tokenId][executor] = permissions;
        emit UsageAuthorized(tokenId, executor);
    }

    /// @notice Check if an address is authorized for a token
    /// @param tokenId Token ID to check
    /// @param executor Address to check authorization for
    /// @return True if authorized
    function isAuthorized(uint256 tokenId, address executor) external view returns (bool) {
        return _authorizations[tokenId][executor].length > 0;
    }

    /// @notice Get permissions for an executor on a token
    /// @param tokenId Token ID to check
    /// @param executor Address to check permissions for
    /// @return Permission bytes
    function getPermissions(uint256 tokenId, address executor) external view returns (bytes memory) {
        return _authorizations[tokenId][executor];
    }

    /* ========== GETTER FUNCTIONS ========== */

    /// @notice Get metadata hash for a token
    /// @param tokenId Token ID to query
    /// @return Metadata hash
    function getMetadataHash(uint256 tokenId) external view returns (bytes32) {
        if (_ownerOf(tokenId) == address(0)) revert InvalidTokenId();
        return _metadataHashes[tokenId];
    }

    /// @notice Get encrypted URI for a token
    /// @param tokenId Token ID to query
    /// @return Encrypted URI string
    function getEncryptedURI(uint256 tokenId) external view returns (string memory) {
        if (_ownerOf(tokenId) == address(0)) revert InvalidTokenId();
        return _encryptedURIs[tokenId];
    }

    /// @notice Get token URI for a token (contains traits schema)
    /// @param tokenId Token ID to query
    /// @return Token URI string
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        if (_ownerOf(tokenId) == address(0)) revert InvalidTokenId();
        return _tokenURIs[tokenId];
    }

    /// @notice Get the next token ID that will be minted
    /// @return Next token ID
    function getNextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    /// @notice Get total number of tokens minted
    /// @return Total supply
    function totalSupply() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    /* ========== METADATA UPDATE ========== */

    /// @notice Update metadata access during transfer with oracle proof
    /// @param tokenId Token ID to update
    /// @param newOwner New owner address
    /// @param sealedKey Sealed key for new owner
    /// @param proof Oracle proof containing new metadata
    function _updateMetadataAccess(
        uint256 tokenId,
        address newOwner,
        bytes calldata sealedKey,
        bytes calldata proof
    ) internal {
        // Extract new metadata hash from proof
        bytes32 newHash = bytes32(proof[0:32]);
        _metadataHashes[tokenId] = newHash;
        
        // Update encrypted URI if provided in proof
        if (proof.length > 64) {
            string memory newURI = string(proof[64:]);
            _encryptedURIs[tokenId] = newURI;
        }
        
        emit MetadataUpdated(tokenId, newHash);
    }

    /* ========== ORACLE VERIFICATION ========== */

    /// @notice Verify oracle proof for operations
    /// @param proof Proof bytes to verify
    /// @return True if proof is valid
    function verifyProof(bytes calldata proof) external view returns (bool) {
        return IOracle(oracle).verifyProof(proof);
    }
}
