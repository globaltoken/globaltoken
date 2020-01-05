// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <globaltoken/treasury.h>

CTreasuryMempool activeTreasury;

bool CTreasuryProposal::IsNull() const
{
    return (nVersion == 0);
}

void CTreasuryMempool::SetTreasuryDir (const std::string &dir)
{
    strTreasuryDir = dir;
}

void CTreasuryMempool::SetTreasuryFile (const std::string &file)
{
    strTreasuryFile = file;
}

std::string CTreasuryMempool::GetTreasuryDir () const
{
    return strTreasuryDir;
}

std::string CTreasuryMempool::GetTreasuryFile () const
{
    return strTreasuryFile;
}

bool CTreasuryMempool::IsCached() const
{
    return (nVersion != 0);
}

void CTreasuryMempool::SetVersion (const uint32_t nNewVersion)
{
    nVersion = nNewVersion;
}

void CTreasuryMempool::SetLastSaved (const uint32_t nNewLastSaved)
{
    nLastSaved = nNewLastSaved;
}

uint32_t CTreasuryMempool::GetVersion() const
{
    return nVersion;
}

uint32_t CTreasuryMempool::GetLastSaved() const
{
    return nLastSaved;
}