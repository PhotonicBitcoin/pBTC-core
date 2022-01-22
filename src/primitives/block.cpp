// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <hash.h>
#include <tinyformat.h>
#include "chainparams.h"
#include "crypto/progpow.h"

uint256 CBlockHeader::GetHash() const
{
    return GetPoWHash();
}

uint256 CBlockHeader::GetHashFull(uint256& mix_hash) const {
    if (IsProgPow()) {
        return GetProgPowHashFull(mix_hash);
    }
    return GetHash();
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 seed;
    CSHA3_256().Write(hashPrevBlock.begin(), 32).Finalize(seed.begin());
    uint64_t matrix[64*64];
    GenerateHeavyHashMatrix(seed, matrix);
    return SerializeHeavyHash(*this, matrix);
}

bool CBlockHeader::IsProgPow() const {
    // This isnt ideal, but suffers from the same issue as the IsMTP() call above. Also can't get
    // chainActive/mapBlockIndex in the consensus library (without disabling binary hardening)..
    return (nTime > 1638883932 && nTime >= Params().GetConsensus().nPPSwitchTime);
}

CProgPowHeader CBlockHeader::GetProgPowHeader() const {
    return CProgPowHeader {
        nVersion,
        hashPrevBlock,
        hashMerkleRoot,
        nTime,
        nBits,
        nHeight,
        nNonce64,
        mix_hash
    };
}

uint256 CBlockHeader::GetProgPowHeaderHash() const 
{
    return SerializeHash(GetProgPowHeader());
}

uint256 CBlockHeader::GetProgPowHashFull(uint256& mix_hash) const {
    return progpow_hash_full(GetProgPowHeader(), mix_hash);
}

uint256 CBlockHeader::GetProgPowHashLight() const {
    return progpow_hash_light(GetProgPowHeader());
}
std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
