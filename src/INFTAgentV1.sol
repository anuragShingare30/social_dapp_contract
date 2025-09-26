// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// SocialINFTAgent.sol
/// - Social AI Agent NFT contract for decentralized social interactions
/// - Stores encrypted URI, metadata hash, agentDID, memoryRoot
/// - Allows agent-to-agent interactions with reputation system
/// - Supports social features: following, collaboration, messaging
/// - Enhanced permission system for fine-grained access control
/// - Batch operations for efficient multi-agent interactions
/// - Agent interaction history and reputation tracking

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IOracleVerifier {
    /// verifyProof should validate cryptographic attestation
    /// and return true if the proof authorizes the requested operation.
    function verifyProof(bytes calldata proof, bytes calldata context) external view returns (bool);
}

contract SocialINFTAgent is ERC721URIStorage, Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    /* ========== STRUCTS ========== */
    struct Metadata {
        bytes32 metadataHash;     // content hash (owner can verify)
        string encryptedURI;      // encrypted pointer (off-chain)
        string agentDID;          // Agentverse DID pointer
        string memoryRoot;        // CID on 0G DA / IPFS for logs
        bool personaLocked;       // lock persona to prevent edits
        uint256 createdAt;        // creation timestamp
        string agentType;         // agent category (e.g., "assistant", "companion", "specialist")
    }

    struct AgentAuth {
        bytes permissions;        // arbitrary permission blob (off-chain semantic)
        uint256 expiresAt;        // unix expiry timestamp (0 = no expiry)
        bool canInteract;         // can interact with other agents
        bool canUpdate;           // can update agent memory
        bool canTransfer;         // can initiate transfers
    }

    struct SocialConnection {
        bool isFollowing;         // is following this agent
        bool isCollaborating;     // active collaboration
        uint256 reputationScore;  // reputation with this agent (0-100)
        uint256 lastInteraction;  // timestamp of last interaction
    }

    struct AgentReputation {
        uint256 totalInteractions;     // total number of interactions
        uint256 positiveRatings;       // positive ratings received
        uint256 collaborationCount;    // successful collaborations
        uint256 trustScore;           // computed trust score (0-1000)
        mapping(address => bool) hasRated; // prevent double rating
    }

    /* ========== STATE ========== */
    uint256 private _tokenIdCounter; // starts at 1
    mapping(uint256 => Metadata) private _meta;
    // tokenId => agentAddress => AgentAuth
    mapping(uint256 => mapping(address => AgentAuth)) public agentAuthorizations;

    // Nonces for owner signatures per token (prevents replay)
    mapping(uint256 => uint256) public ownerNonces;

    // Oracle verifier contract
    address public oracleVerifier;

    // Social features
    mapping(uint256 => mapping(uint256 => SocialConnection)) public socialConnections; // tokenId => targetTokenId => connection
    mapping(uint256 => AgentReputation) public agentReputations;
    mapping(uint256 => uint256[]) public agentFollowers; // tokenId => follower tokenIds
    mapping(uint256 => uint256[]) public agentFollowing; // tokenId => following tokenIds
    
    // Interaction history
    mapping(uint256 => bytes32[]) public interactionHistory; // tokenId => interaction hashes
    mapping(bytes32 => bool) public processedInteractions; // prevent replay attacks
    
    // Minting control
    uint256 public mintPrice;
    bool public publicMintEnabled;
    mapping(address => bool) public authorizedMinters;

    /* ========== EVENTS ========== */
    event MetadataUpdated(uint256 indexed tokenId, bytes32 metadataHash);
    event EncryptedURIUpdated(uint256 indexed tokenId, string encryptedURI);
    event AgentDIDUpdated(uint256 indexed tokenId, string agentDID);
    event MemoryRootUpdated(uint256 indexed tokenId, string memoryRoot);
    event PersonaLocked(uint256 indexed tokenId);

    event AgentAuthorized(uint256 indexed tokenId, address indexed agent, bytes permissions, uint256 expiresAt);
    event AgentRevoked(uint256 indexed tokenId, address indexed agent);
    event AgentActionExecuted(uint256 indexed tokenId, address indexed agent, bytes action);

    event TransferWithProof(address indexed from, address indexed to, uint256 indexed tokenId);
    
    // Social events
    event AgentFollowed(uint256 indexed followerTokenId, uint256 indexed targetTokenId);
    event AgentUnfollowed(uint256 indexed followerTokenId, uint256 indexed targetTokenId);
    event AgentInteraction(uint256 indexed agentA, uint256 indexed agentB, bytes32 interactionHash, string interactionType);
    event ReputationUpdated(uint256 indexed tokenId, uint256 newTrustScore);
    event CollaborationStarted(uint256 indexed agentA, uint256 indexed agentB, bytes32 collaborationId);
    event CollaborationCompleted(uint256 indexed agentA, uint256 indexed agentB, bytes32 collaborationId, bool successful);

    /* ========== ERRORS ========== */
    error NotTokenOwner();
    error PersonaAlreadyLocked();
    error AgentNotAuthorized();
    error SignatureExpired();
    error InvalidSignature();
    error OracleVerificationFailed();
    error ZeroAddress();

    /* ========== CONSTRUCTOR ========== */
    constructor(string memory name_, string memory symbol_, address initialOracleVerifier) ERC721(name_, symbol_) Ownable(msg.sender) {
        require(initialOracleVerifier != address(0), "zero oracle");
        oracleVerifier = initialOracleVerifier;
        // start token IDs at 1
        _tokenIdCounter = 1;
        // Initialize minting settings
        mintPrice = 0.001 ether; // Default mint price
        publicMintEnabled = true;
    }

    /* ========== OWNER ADMIN ========== */

    function setOracleVerifier(address newVerifier) external onlyOwner {
        require(newVerifier != address(0), "zero address");
        oracleVerifier = newVerifier;
    }

    /* ========== MINT / BURN ========== */

    /// @notice mint a new iNFT with metadata pointers
    function mint(
        address to,
        string calldata tokenURI_,
        bytes32 metadataHash,
        string calldata agentDID,
        string calldata memoryRoot,
        string calldata encryptedURI,
        string calldata agentType
    ) external payable returns (uint256) {
        require(to != address(0), "mint to zero");
        require(
            msg.sender == owner() || 
            authorizedMinters[msg.sender] || 
            (publicMintEnabled && msg.value >= mintPrice),
            "not authorized to mint"
        );
        
        uint256 tokenId = _tokenIdCounter;
        _tokenIdCounter++;

        _safeMint(to, tokenId);
        _setTokenURI(tokenId, tokenURI_);

        _meta[tokenId] = Metadata({
            metadataHash: metadataHash,
            encryptedURI: encryptedURI,
            agentDID: agentDID,
            memoryRoot: memoryRoot,
            personaLocked: false,
            createdAt: block.timestamp,
            agentType: agentType
        });

        // Initialize reputation
        agentReputations[tokenId].trustScore = 500; // Start with neutral reputation

        emit MetadataUpdated(tokenId, metadataHash);
        emit EncryptedURIUpdated(tokenId, encryptedURI);
        emit AgentDIDUpdated(tokenId, agentDID);
        emit MemoryRootUpdated(tokenId, memoryRoot);

        return tokenId;
    }

    /// @notice burn a token (owner only for future extension)
    function burn(uint256 tokenId) external onlyOwner {
        require(_ownerOf(tokenId) != address(0), "not exist");
        _burn(tokenId);
        delete _meta[tokenId];
    }

    /* ========== GETTERS ========== */

    function getMetadataHash(uint256 tokenId) external view returns (bytes32) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].metadataHash;
    }

    function getEncryptedURI(uint256 tokenId) external view returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].encryptedURI;
    }

    function getAgentDID(uint256 tokenId) external view returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].agentDID;
    }

    function getMemoryRoot(uint256 tokenId) external view returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].memoryRoot;
    }

    function isPersonaLocked(uint256 tokenId) external view returns (bool) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].personaLocked;
    }

    function getAgentType(uint256 tokenId) external view returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].agentType;
    }

    function getCreatedAt(uint256 tokenId) external view returns (uint256) {
        require(_ownerOf(tokenId) != address(0), "not exist");
        return _meta[tokenId].createdAt;
    }

    function getSocialConnection(uint256 tokenIdA, uint256 tokenIdB) external view returns (
        bool isFollowing,
        bool isCollaborating,
        uint256 reputationScore,
        uint256 lastInteraction
    ) {
        SocialConnection storage connection = socialConnections[tokenIdA][tokenIdB];
        return (
            connection.isFollowing,
            connection.isCollaborating,
            connection.reputationScore,
            connection.lastInteraction
        );
    }

    /* ========== OWNER ACTIONS (token owner) ========== */

    modifier onlyTokenOwner(uint256 tokenId) {
        if (_ownerOf(tokenId) == address(0) || ownerOf(tokenId) != msg.sender) revert NotTokenOwner();
        _;
    }

    function updateEncryptedURI(uint256 tokenId, string calldata encryptedURI) external onlyTokenOwner(tokenId) {
        _meta[tokenId].encryptedURI = encryptedURI;
        emit EncryptedURIUpdated(tokenId, encryptedURI);
    }

    function updateMetadataHash(uint256 tokenId, bytes32 metadataHash) external onlyTokenOwner(tokenId) {
        _meta[tokenId].metadataHash = metadataHash;
        emit MetadataUpdated(tokenId, metadataHash);
    }

    function updateAgentDID(uint256 tokenId, string calldata agentDID) external onlyTokenOwner(tokenId) {
        _meta[tokenId].agentDID = agentDID;
        emit AgentDIDUpdated(tokenId, agentDID);
    }

    function updateMemoryRoot(uint256 tokenId, string calldata memoryRoot) external onlyTokenOwner(tokenId) {
        _meta[tokenId].memoryRoot = memoryRoot;
        emit MemoryRootUpdated(tokenId, memoryRoot);
    }

    function lockPersona(uint256 tokenId) external onlyTokenOwner(tokenId) {
        _meta[tokenId].personaLocked = true;
        emit PersonaLocked(tokenId);
    }

    /* ========== AGENT AUTHORIZATION ========== */

    /// @notice owner authorizes an agent address with detailed permissions
    function authorizeAgent(
        uint256 tokenId,
        address agent,
        bytes calldata permissions,
        uint256 expiresAt,
        bool canInteract,
        bool canUpdate,
        bool canTransfer
    ) external onlyTokenOwner(tokenId) {
        require(agent != address(0), "agent zero");
        agentAuthorizations[tokenId][agent] = AgentAuth({
            permissions: permissions,
            expiresAt: expiresAt,
            canInteract: canInteract,
            canUpdate: canUpdate,
            canTransfer: canTransfer
        });
        emit AgentAuthorized(tokenId, agent, permissions, expiresAt);
    }

    function revokeAgent(uint256 tokenId, address agent) external onlyTokenOwner(tokenId) {
        delete agentAuthorizations[tokenId][agent];
        emit AgentRevoked(tokenId, agent);
    }

    function isAgentAuthorized(uint256 tokenId, address agent) public view returns (bool) {
        AgentAuth memory a = agentAuthorizations[tokenId][agent];
        if (a.expiresAt == 0) {
            // if permission blob exists (non-empty) treat as authorized
            return a.permissions.length != 0;
        } else {
            return a.permissions.length != 0 && block.timestamp < a.expiresAt;
        }
    }

    /* ========== AGENT ACTION EXECUTION (owner-signed) ========== */

    /// Owner-signed "action" performed by agent (off-chain or on-chain action payload)
    /// - action: arbitrary bytes containing action instruction (semantic defined off-chain)
    /// - deadline: unix timestamp for signature expiry
    /// - v,r,s: owner signature (over structured message)
    function agentExecuteWithOwnerSig(
        uint256 tokenId,
        bytes calldata action,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        address agentCaller = msg.sender;
        if (!isAgentAuthorized(tokenId, agentCaller)) revert AgentNotAuthorized();

        if (deadline != 0 && block.timestamp > deadline) revert SignatureExpired();

        // Build structured message hash: tokenId + action + ownerNonce + deadline + address(this)
        uint256 nonce = ownerNonces[tokenId];
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encodePacked(tokenId, action, nonce, deadline, address(this)))
        ));

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != ownerOf(tokenId)) revert InvalidSignature();

        // consume nonce
        ownerNonces[tokenId] = nonce + 1;

        // Route action to be interpreted off-chain by Agentverse or perform minimal on-chain tags
        // Here we only emit an event; off-chain watcher will perform the semantic action.
        emit AgentActionExecuted(tokenId, agentCaller, action);
    }

    /* ========== TRANSFER WITH ORACLE PROOF ========== */

    /// Transfer pattern that allows a verified off-chain oracle to provide the sealed key / updated metadata.
    /// proof: opaque proof bytes; context: optional context bytes for the oracle (e.g., encoded tokenId/from/to)
    function transferWithOracleProof(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata /* sealedKey */,
        bytes calldata proof,
        bytes calldata context
    ) external nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (ownerOf(tokenId) != from) revert NotTokenOwner();
        // Verify via oracle
        bool ok = IOracleVerifier(oracleVerifier).verifyProof(proof, context);
        if (!ok) revert OracleVerificationFailed();

        // If proof contains new metadataHash or encryptedURI, the off-chain oracle convention should
        // make sure the context or proof encodes those and the watcher updates via owner action.
        // For gas minimization we don't parse proof (oracle trusted to verify).
        // Transfer ownership
        _transfer(from, to, tokenId);

        // Store sealedKey hash on-chain as an event for transparency (not the sealedKey itself)
        emit TransferWithProof(from, to, tokenId);
        // Off-chain: Agentverse and new owner will use sealedKey via secure channel (not saved on-chain)
    }

    /* ========== SOCIAL INTERACTIONS ========== */

    /// @notice Follow another agent
    function followAgent(uint256 followerTokenId, uint256 targetTokenId) external onlyTokenOwner(followerTokenId) {
        require(_ownerOf(targetTokenId) != address(0), "target not exist");
        require(followerTokenId != targetTokenId, "cannot follow self");
        require(!socialConnections[followerTokenId][targetTokenId].isFollowing, "already following");

        socialConnections[followerTokenId][targetTokenId].isFollowing = true;
        socialConnections[followerTokenId][targetTokenId].lastInteraction = block.timestamp;
        
        agentFollowers[targetTokenId].push(followerTokenId);
        agentFollowing[followerTokenId].push(targetTokenId);

        emit AgentFollowed(followerTokenId, targetTokenId);
    }

    /// @notice Unfollow an agent
    function unfollowAgent(uint256 followerTokenId, uint256 targetTokenId) external onlyTokenOwner(followerTokenId) {
        require(socialConnections[followerTokenId][targetTokenId].isFollowing, "not following");

        socialConnections[followerTokenId][targetTokenId].isFollowing = false;
        
        // Remove from arrays (expensive but necessary)
        _removeFromArray(agentFollowers[targetTokenId], followerTokenId);
        _removeFromArray(agentFollowing[followerTokenId], targetTokenId);

        emit AgentUnfollowed(followerTokenId, targetTokenId);
    }

    /// @notice Record an interaction between two agents
    function recordInteraction(
        uint256 agentA, 
        uint256 agentB, 
        string calldata interactionType,
        bytes calldata interactionData
    ) external {
        require(_ownerOf(agentA) != address(0) && _ownerOf(agentB) != address(0), "agents not exist");
        require(
            isAgentAuthorized(agentA, msg.sender) || ownerOf(agentA) == msg.sender ||
            isAgentAuthorized(agentB, msg.sender) || ownerOf(agentB) == msg.sender,
            "not authorized"
        );

        bytes32 interactionHash = keccak256(abi.encodePacked(
            agentA, agentB, interactionType, interactionData, block.timestamp
        ));
        
        require(!processedInteractions[interactionHash], "interaction already processed");
        processedInteractions[interactionHash] = true;

        // Update interaction history
        interactionHistory[agentA].push(interactionHash);
        interactionHistory[agentB].push(interactionHash);

        // Update reputation counters
        agentReputations[agentA].totalInteractions++;
        agentReputations[agentB].totalInteractions++;

        // Update social connections
        socialConnections[agentA][agentB].lastInteraction = block.timestamp;
        socialConnections[agentB][agentA].lastInteraction = block.timestamp;

        emit AgentInteraction(agentA, agentB, interactionHash, interactionType);
    }

    /// @notice Rate an agent after interaction
    function rateAgent(uint256 raterTokenId, uint256 targetTokenId, bool positive) external onlyTokenOwner(raterTokenId) {
        require(_ownerOf(targetTokenId) != address(0), "target not exist");
        require(raterTokenId != targetTokenId, "cannot rate self");
        require(!agentReputations[targetTokenId].hasRated[msg.sender], "already rated");

        agentReputations[targetTokenId].hasRated[msg.sender] = true;
        
        if (positive) {
            agentReputations[targetTokenId].positiveRatings++;
            socialConnections[raterTokenId][targetTokenId].reputationScore = 
                (socialConnections[raterTokenId][targetTokenId].reputationScore + 10) > 100 ? 
                100 : socialConnections[raterTokenId][targetTokenId].reputationScore + 10;
        } else {
            socialConnections[raterTokenId][targetTokenId].reputationScore = 
                socialConnections[raterTokenId][targetTokenId].reputationScore < 10 ? 
                0 : socialConnections[raterTokenId][targetTokenId].reputationScore - 10;
        }

        // Recalculate trust score
        _updateTrustScore(targetTokenId);
    }

    /// @notice Start a collaboration between two agents
    function startCollaboration(uint256 agentA, uint256 agentB) external {
        require(_ownerOf(agentA) != address(0) && _ownerOf(agentB) != address(0), "agents not exist");
        require(
            ownerOf(agentA) == msg.sender || ownerOf(agentB) == msg.sender,
            "must own one of the agents"
        );

        bytes32 collaborationId = keccak256(abi.encodePacked(agentA, agentB, block.timestamp));
        
        socialConnections[agentA][agentB].isCollaborating = true;
        socialConnections[agentB][agentA].isCollaborating = true;

        emit CollaborationStarted(agentA, agentB, collaborationId);
    }

    /// @notice Complete a collaboration
    function completeCollaboration(uint256 agentA, uint256 agentB, bool successful) external {
        require(
            socialConnections[agentA][agentB].isCollaborating,
            "no active collaboration"
        );
        require(
            ownerOf(agentA) == msg.sender || ownerOf(agentB) == msg.sender,
            "must own one of the agents"
        );

        socialConnections[agentA][agentB].isCollaborating = false;
        socialConnections[agentB][agentA].isCollaborating = false;

        if (successful) {
            agentReputations[agentA].collaborationCount++;
            agentReputations[agentB].collaborationCount++;
            _updateTrustScore(agentA);
            _updateTrustScore(agentB);
        }

        bytes32 collaborationId = keccak256(abi.encodePacked(agentA, agentB, "completed"));
        emit CollaborationCompleted(agentA, agentB, collaborationId, successful);
    }

    /* ========== ADMIN FUNCTIONS ========== */

    function setMintPrice(uint256 newPrice) external onlyOwner {
        mintPrice = newPrice;
    }

    function setPublicMintEnabled(bool enabled) external onlyOwner {
        publicMintEnabled = enabled;
    }

    function setAuthorizedMinter(address minter, bool authorized) external onlyOwner {
        authorizedMinters[minter] = authorized;
    }

    function withdrawFees() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    /* ========== VIEW FUNCTIONS ========== */

    function getAgentFollowers(uint256 tokenId) external view returns (uint256[] memory) {
        return agentFollowers[tokenId];
    }

    function getAgentFollowing(uint256 tokenId) external view returns (uint256[] memory) {
        return agentFollowing[tokenId];
    }

    function getAgentReputation(uint256 tokenId) external view returns (
        uint256 totalInteractions,
        uint256 positiveRatings,
        uint256 collaborationCount,
        uint256 trustScore
    ) {
        AgentReputation storage rep = agentReputations[tokenId];
        return (rep.totalInteractions, rep.positiveRatings, rep.collaborationCount, rep.trustScore);
    }

    function getInteractionHistory(uint256 tokenId) external view returns (bytes32[] memory) {
        return interactionHistory[tokenId];
    }

    /* ========== INTERNAL FUNCTIONS ========== */

    function _updateTrustScore(uint256 tokenId) internal {
        AgentReputation storage rep = agentReputations[tokenId];
        
        // Calculate trust score based on positive ratings, collaborations, and total interactions
        uint256 score = 500; // Base score
        
        if (rep.totalInteractions > 0) {
            uint256 positiveRatio = (rep.positiveRatings * 100) / rep.totalInteractions;
            score = (score * positiveRatio) / 100;
        }
        
        // Bonus for collaborations
        score += rep.collaborationCount * 10;
        
        // Cap at 1000
        rep.trustScore = score > 1000 ? 1000 : score;
        
        emit ReputationUpdated(tokenId, rep.trustScore);
    }

    function _removeFromArray(uint256[] storage array, uint256 value) internal {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == value) {
                array[i] = array[array.length - 1];
                array.pop();
                break;
            }
        }
    }

    /* ========== OVERRIDES ========== */
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        address result = super._update(to, tokenId, auth);
        
        // If this is a burn operation (to == address(0)), clean up metadata
        if (to == address(0) && from != address(0)) {
            delete _meta[tokenId];
        }
        
        return result;
    }

    function tokenURI(uint256 tokenId) public view override(ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }
}
