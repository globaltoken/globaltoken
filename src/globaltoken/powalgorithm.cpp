// Copyright (c) 2009-2019 The DigiByte Core developers
// Copyright (c) 2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <globaltoken/powalgorithm.h>

#include <sstream>
#include <vector>
#include <algorithm>

std::string GetAlgoName(uint8_t Algo)
{
    switch (Algo)
    {
        case ALGO_SHA256D:
            return std::string("sha256d");
        case ALGO_SCRYPT:
            return std::string("scrypt");
        case ALGO_X11:
            return std::string("x11");
        case ALGO_NEOSCRYPT:
            return std::string("neoscrypt");
        case ALGO_YESCRYPT:
            return std::string("yescrypt");
        case ALGO_EQUIHASH:
            return std::string("equihash");
        case ALGO_HMQ1725:
            return std::string("hmq1725");
        case ALGO_XEVAN:
            return std::string("xevan");
        case ALGO_NIST5:
            return std::string("nist5");
        case ALGO_TIMETRAVEL10:
            return std::string("timetravel10");
        case ALGO_PAWELHASH:
            return std::string("pawelhash");
        case ALGO_X13:
            return std::string("x13");
        case ALGO_X14:
            return std::string("x14");
        case ALGO_X15:
            return std::string("x15");
        case ALGO_X17:
            return std::string("x17");
        case ALGO_LYRA2REV2:
            return std::string("lyra2rev2");
        case ALGO_BLAKE2S:
            return std::string("blake2s");
        case ALGO_BLAKE2B:
            return std::string("blake2b");
        case ALGO_ASTRALHASH:
            return std::string("astralhash");
        case ALGO_PADIHASH:
            return std::string("padihash");
        case ALGO_JEONGHASH:
            return std::string("jeonghash");
        case ALGO_KECCAKC:
            return std::string("keccakc");
        case ALGO_ZHASH:
            return std::string("zhash");
        case ALGO_GLOBALHASH:
            return std::string("globalhash");
        case ALGO_SKEIN:
            return std::string("skein");
        case ALGO_GROESTL:
            return std::string("groestl");
        case ALGO_QUBIT:
            return std::string("qubit");
        case ALGO_SKUNKHASH:
            return std::string("skunkhash");
        case ALGO_QUARK:
            return std::string("quark");
        case ALGO_X16R:
            return std::string("x16r");
        case ALGO_LYRA2REV3:
            return std::string("lyra2rev3");
        case ALGO_YESCRYPT_R16V2:
            return std::string("yescryptr16v2");
        case ALGO_YESCRYPT_R24:
            return std::string("yescryptr24");
        case ALGO_YESCRYPT_R8:
            return std::string("yescryptr8");
        case ALGO_YESCRYPT_R32:
            return std::string("yescryptr32");
        case ALGO_BCRYPT:
            return std::string("bcrypt");
        case ALGO_ARGON2D:
            return std::string("argon2d");
        case ALGO_ARGON2I:
            return std::string("argon2i");
        case ALGO_CPU23R:
            return std::string("cpu23r");
        case ALGO_YESPOWER:
            return std::string("yespower");
        case ALGO_X21S:
            return std::string("x21s");
        case ALGO_X16S:
            return std::string("x16s");
        case ALGO_X22I:
            return std::string("x22i");
        case ALGO_LYRA2Z:
            return std::string("lyra2z");
        case ALGO_HONEYCOMB:
            return std::string("honeycomb");
        case ALGO_EH192:
            return std::string("equihash192");
        case ALGO_MARS:
            return std::string("mars");
        case ALGO_X12:
            return std::string("x12");
        case ALGO_HEX:
            return std::string("hex");
        case ALGO_DEDAL:
            return std::string("dedal");
        case ALGO_C11:
            return std::string("c11");
        case ALGO_PHI1612:
            return std::string("phi1612");
        case ALGO_PHI2:
            return std::string("phi2");
        case ALGO_X16RT:
            return std::string("x16rt");
        case ALGO_TRIBUS:
            return std::string("tribus");
        case ALGO_ALLIUM:
            return std::string("allium");
        case ALGO_ARCTICHASH:
            return std::string("arctichash");
        case ALGO_DESERTHASH:
            return std::string("deserthash");
        case ALGO_CRYPTOANDCOFFEE:
            return std::string("cryptoandcoffee");
        case ALGO_RICKHASH:
            return std::string("rickhash");
    }
    return std::string("unknown");       
}

uint8_t GetAlgoByName(std::string strAlgo, uint8_t fallback, bool &fAlgoFound)
{
    transform(strAlgo.begin(),strAlgo.end(),strAlgo.begin(),::tolower);
    fAlgoFound = true;
    if (strAlgo == "sha" || strAlgo == "sha256" || strAlgo == "sha256d")
        return ALGO_SHA256D;
    else if (strAlgo == "scrypt")
        return ALGO_SCRYPT;
    else if (strAlgo == "neoscrypt")
        return ALGO_NEOSCRYPT;
    else if (strAlgo == "equihash" || strAlgo == "zcash" || strAlgo == "equihash200" || strAlgo == "equihash2009" || strAlgo == "equihash200.9")
        return ALGO_EQUIHASH;
    else if (strAlgo == "yescrypt")
        return ALGO_YESCRYPT;
    else if (strAlgo == "hmq1725")
        return ALGO_HMQ1725;
    else if (strAlgo == "xevan")
        return ALGO_XEVAN;
    else if (strAlgo == "nist5")
        return ALGO_NIST5;
    else if (strAlgo == "timetravel" || strAlgo == "timetravel10")
        return ALGO_TIMETRAVEL10;
    else if (strAlgo == "pawelhash")
        return ALGO_PAWELHASH;
    else if (strAlgo == "x11")
        return ALGO_X11;
    else if (strAlgo == "x13")
        return ALGO_X13;
    else if (strAlgo == "x14")
        return ALGO_X14;
    else if (strAlgo == "x15")
        return ALGO_X15;
    else if (strAlgo == "x16r")
        return ALGO_X16R;
    else if (strAlgo == "x17")
        return ALGO_X17;
    else if (strAlgo == "lyra" || strAlgo == "lyra2re" || strAlgo == "lyra2" || strAlgo == "lyra2rev2")
        return ALGO_LYRA2REV2;
    else if (strAlgo == "blake2s")
        return ALGO_BLAKE2S;
    else if (strAlgo == "blake2b" || strAlgo == "sia")
        return ALGO_BLAKE2B;
    else if (strAlgo == "astralhash")
        return ALGO_ASTRALHASH;
    else if (strAlgo == "padihash")
        return ALGO_PADIHASH;
    else if (strAlgo == "jeonghash")
        return ALGO_JEONGHASH;
    else if (strAlgo == "keccak" || strAlgo == "keccakc")
        return ALGO_KECCAKC;
    else if (strAlgo == "zhash" || strAlgo == "equihash144" || strAlgo == "equihash1445" || strAlgo == "equihash144_5" || strAlgo == "equihash144.5")
        return ALGO_ZHASH;
    else if (strAlgo == "globalhash")
        return ALGO_GLOBALHASH;
    else if (strAlgo == "groestl" || strAlgo == "groestlsha2")
        return ALGO_GROESTL;
    else if (strAlgo == "skein" || strAlgo == "skeinsha2")
        return ALGO_SKEIN;
    else if (strAlgo == "q2c" || strAlgo == "qubit")
        return ALGO_QUBIT;
    else if (strAlgo == "skunk" || strAlgo == "skunkhash")
        return ALGO_SKUNKHASH;
    else if (strAlgo == "quark")
        return ALGO_QUARK;
    else if (strAlgo == "lyra2rev3")
        return ALGO_LYRA2REV3;
    else if (strAlgo == "yescryptr16v2")
        return ALGO_YESCRYPT_R16V2;
    else if (strAlgo == "yescryptr24")
        return ALGO_YESCRYPT_R24;
    else if (strAlgo == "yescryptr8")
        return ALGO_YESCRYPT_R8;
    else if (strAlgo == "yescryptr32")
        return ALGO_YESCRYPT_R32;
    else if (strAlgo == "bcrypt")
        return ALGO_BCRYPT;
    else if (strAlgo == "argon2d")
        return ALGO_ARGON2D;
    else if (strAlgo == "argon2i")
        return ALGO_ARGON2I;
    else if (strAlgo == "cpu23r")
        return ALGO_CPU23R;
    else if (strAlgo == "yespower")
        return ALGO_YESPOWER;
    else if (strAlgo == "x21s")
        return ALGO_X21S;
    else if (strAlgo == "x16s")
        return ALGO_X16S;
    else if (strAlgo == "x22i")
        return ALGO_X22I;
    else if (strAlgo == "lyra2z")
        return ALGO_LYRA2Z;
    else if (strAlgo == "honeycomb")
        return ALGO_HONEYCOMB;
    else if (strAlgo == "equihash192" || strAlgo == "equihash1927" || strAlgo == "equihash192.7" || strAlgo == "equihash192_7")
        return ALGO_EH192;
    else if (strAlgo == "mars" || strAlgo == "equihash96" || strAlgo == "equihash965" || strAlgo == "equihash96_5" || strAlgo == "equihash96.5")
        return ALGO_MARS;
    else if (strAlgo == "x12")
        return ALGO_X12;
    else if (strAlgo == "hex")
        return ALGO_HEX;
    else if (strAlgo == "dedal")
        return ALGO_DEDAL;
    else if (strAlgo == "c11")
        return ALGO_C11;
    else if (strAlgo == "phi1612" || strAlgo == "phi1" || strAlgo == "phi")
        return ALGO_PHI1612;
    else if (strAlgo == "phi2")
        return ALGO_PHI2;
    else if (strAlgo == "x16rt")
        return ALGO_X16RT;
    else if (strAlgo == "tribus")
        return ALGO_TRIBUS;
    else if (strAlgo == "allium")
        return ALGO_ALLIUM;
    else if (strAlgo == "arctichash")
        return ALGO_ARCTICHASH;
    else if (strAlgo == "deserthash")
        return ALGO_DESERTHASH;
    else if (strAlgo == "cryptoandcoffee")
        return ALGO_CRYPTOANDCOFFEE;
    else if (strAlgo == "rickhash")
        return ALGO_RICKHASH;
    else
    {
        fAlgoFound = false;
        return fallback;
    }
}

std::string GetAlgoRangeString()
{
    std::vector <std::string> vAlgoStrings;
    std::stringstream strStream;
    for(uint8_t i = 0; i < NUM_ALGOS; i++)
    {
        vAlgoStrings.push_back(GetAlgoName(i));
    }
    // Sort all algos in alphabetical order
    std::sort(vAlgoStrings.begin(), vAlgoStrings.end());
    size_t nWhileIndex = 0;
    while(nWhileIndex < vAlgoStrings.size())
    {
        if(nWhileIndex == vAlgoStrings.size()-1)
            strStream << vAlgoStrings[nWhileIndex];
        else
            strStream << vAlgoStrings[nWhileIndex] << ", ";
        nWhileIndex++;
    }
    return strStream.str();
}

bool IsAlgoAllowedBeforeHF2(uint8_t nAlgo)
{
    // Hardfork 1 starts with algo sha256 and ends with last algo id x16r
    return (nAlgo >= ALGO_SHA256D && nAlgo <= ALGO_X16R);
}

bool IsEquihashBasedAlgo(uint8_t nAlgo)
{
    return (nAlgo == ALGO_EQUIHASH || nAlgo == ALGO_ZHASH || nAlgo == ALGO_EH192 || nAlgo == ALGO_MARS);
}

std::string GetEquihashBasedDefaultPersonalize(uint8_t nAlgo)
{
    assert(IsEquihashBasedAlgo(nAlgo));
    switch(nAlgo)
    {
        case ALGO_EQUIHASH:
            return std::string("ZcashPoW");
        case ALGO_ZHASH:
            return std::string("GLTZhash");
        case ALGO_EH192:
            return std::string("GLTEh192");
        case ALGO_MARS:
            return std::string("GLT-Mars");
    }
}