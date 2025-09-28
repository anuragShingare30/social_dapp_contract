# Intelligent NFT (INFT) Smart Contract

## Overview

The INFT contract is an intelligent NFT system designed for AI agents. It extends the standard ERC721 functionality to support encrypted metadata, authorization systems, and oracle-based verification for AI agent interactions.

## Key Features

### AI Agent Support
- **Encrypted URIs**: Store encrypted off-chain data for AI agents
- **Metadata Hashes**: Cryptographic verification of agent metadata
- **Traits Schema**: Token URIs contain structured traits for agent capabilities

### Authorization System
- **Permission-based Access**: Grant specific permissions to addresses for token usage
- **Flexible Permissions**: Custom permission bytes for different use cases
- **Owner Control**: Only token owners can authorize usage

### Oracle Integration
- **Proof Verification**: Oracle-based cryptographic proof validation
- **Metadata Updates**: Secure metadata updates during transfers
- **Attestation Support**: Cryptographic attestation for operations

## Contract Functions

### Minting
```solidity
function mint(
    address to,
    string calldata tokenURI_,
    string calldata encryptedURI,
    bytes32 metadataHash
) external returns (uint256)
```
- Mints new INFT with metadata and encrypted URI
- Returns unique token ID starting from 1

### Authorization Management
```solidity
function authorizeUsage(uint256 tokenId, address executor, bytes calldata permissions) external
function isAuthorized(uint256 tokenId, address executor) external view returns (bool)
function getPermissions(uint256 tokenId, address executor) external view returns (bytes memory)
```
- Authorize addresses to use specific tokens
- Check authorization status
- Retrieve permission details

### Data Access
```solidity
function getMetadataHash(uint256 tokenId) external view returns (bytes32)
function getEncryptedURI(uint256 tokenId) external view returns (string memory)
function tokenURI(uint256 tokenId) public view override returns (string memory)
```
- Access token metadata hash for verification
- Retrieve encrypted URI for off-chain data
- Get token URI with traits schema

## Use Cases

### AI Agent NFTs
- Create NFTs representing AI agents with specific capabilities
- Store encrypted model data or configuration off-chain
- Define agent traits and permissions through metadata

### Access Control
- Grant temporary or permanent usage rights to other addresses
- Implement complex permission systems for AI agent interactions
- Maintain ownership while allowing controlled usage

### Secure Metadata
- Cryptographically verify metadata integrity
- Update metadata securely during transfers
- Protect sensitive AI agent data through encryption

## Security Features

- **Ownership Verification**: Only token owners can authorize usage
- **Input Validation**: Zero address and invalid token ID protection
- **Reentrancy Protection**: Built-in reentrancy guard
- **Oracle Verification**: Cryptographic proof validation

## Events

- `INFTMinted`: Emitted when new INFT is created
- `UsageAuthorized`: Emitted when usage is authorized for an address
- `MetadataUpdated`: Emitted when metadata hash is updated

## Getting Started

1. Deploy the contract with name, symbol, and oracle address
2. Mint INFTs with metadata and encrypted URIs
3. Authorize usage for specific addresses as needed
4. Use oracle proofs for secure operations

## Technical Details

- **Standard**: ERC721 compliant
- **Access Control**: OpenZeppelin Ownable
- **Security**: ReentrancyGuard protection
- **Token IDs**: Sequential starting from 1
- **Metadata**: Hash-based verification system

This contract enables the creation of intelligent, secure NFTs suitable for AI agent representation and interaction within decentralized applications.


## Deployment script on ETH Sepolia Testnet and 0G Testnet

- The deployment script to deploy contract on chain is:

```solidity
// On sepolia testnet
forge build
forge test -vvvv
forge script script/INFTAgentV1Script.s.sol:INFTAgentV1Script --rpc-url $SEPOLIA_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv

// on 0G Testnet
forge script script/INFTAgentV1Script.s.sol:INFTAgentV1Script --rpc-url $0G_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv
```


## Contract address on Sepolia and 0G testnet

```bash
# Sepolia Testnet
Contract Address: 0x1352aba587ffbbc398d7ecaea31e2948d3afe4fb

# 0G testnet
Contract Address: 0x1352aba587ffbbc398d7ecaea31e2948d3afe4fb
```
