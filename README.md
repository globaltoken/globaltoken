GlobalToken Official Development Repository
=====================================

[![Build Status](https://travis-ci.org/globaltoken/globaltoken.svg?branch=master)](https://travis-ci.org/globaltoken/globaltoken)

What is GlobalToken?
----------------
GlobalToken (GLT) is a Proof of Work Multi-Algorithm cryptocurrency. GlobalToken uses peer-to-peer technology to operate with no central authority: managing transactions and issuing money are carried out collectively by the network. GlobalToken Core is the name of open source software which enables the use of this currency.

````
Codebase : Bitcoin
RPC Port: 9320
P2P / Masternode Port : 9319
Masternode Collateral : 50,000 GLT
PoW Phase : Active
Block Size : 10MB
Transaction Size : 1MB
TPM / Transactions Per Minute : 44247
TPS / Transactions Per Second : 737.45
MultiShield Retargeting (DGB powered)
Merged Mining Enabled (NMC powered)
AuxPoW Enabled
Equihash/Zhash (AuxPoW 2.0)
InstantSend Support
````

30 Algorithms Supported
-------
````
1. astralhash
2. blake2b
3. blake2s
4. equihash
5. globalhash
6. myriad-groestl
7. hmq1725
8. jeonghash
9. keccakc
10. lyra2rev2
11. neoscrypt
12. nist5
13. padihash
14. pawelhash
15. quark
16. qubit
17. scrypt
18. sha256d*
19. skein
20. skunkhash
21. timetravel10
22. x11
23. x13
24. x14
25. x15
26. x16r
27. x17
28. xevan
29. yescrypt
30. zhash
````

*sha256d is the default algorithm  
Use "algo=x16r" in globaltoken.conf to change the algorithm in use.

Links
----------------
https://globaltoken.org  
https://explorer.globaltoken.org

Price Info
----------------
https://coinmarketcap.com/currencies/globaltoken/  
https://coingecko.com/en/coins/globaltoken

Social
----------------
https://discord.gg/futDmxM  
https://twitter.com/globaltokencoin  
https://bitcointalk.org/index.php?topic=5035302.0

Mining
----------------
https://gltminer.com/

Running GlobalToken with Docker
----------------
Please install the latest Docker CE and Docker Compose from https://docker.com 

Docker CE  
Linux : https://docs.docker.com/install/linux/docker-ce/ubuntu/  
Windows : https://docs.docker.com/docker-for-windows/install/  
Mac : https://docs.docker.com/docker-for-mac/install/  

Docker Compose  
https://docs.docker.com/compose/install/

There are two ways to run GlobalToken with Docker.  The easiest way to is to use the container from Docker Hub, alternatively you can build your own.  GlobalToken container be found on DockerHub at : ````cryptoandcoffee/globaltoken````  
````
docker pull cryptoandcoffee/globaltoken
````

Run GlobalToken from Docker Hub in the Foreground (press CTRL-C to stop) 
````
docker run cryptoandcoffee/globaltoken
````

Run GlobalToken from Docker Hub in the Background (forever)  
````
docker run -d cryptoandcoffee/globaltoken
````

Run GlobalToken with a permanent volume
````
docker run -d -v ./local_global_token_directory:/root/.globaltoken/cryptoandcoffee/globaltoken cryptoandcoffee/globaltoken
````

Run GlobalToken with a permanent volume and expose a port
````
docker run -d -p 9319:9319 -v ./local_global_token_directory:/root/.globaltoken/ cryptoandcoffee/globaltoken   
````

Run GlobalToken with a permanent volume and expose a port and custom configuration file
````
docker run -d -p 9319:9319 -v ./local_globaltoken.conf:/root/.globaltoken/globaltoken.conf -v ./local_global_token_directory:/root/.globaltoken/ cryptoandcoffee/globaltoken
````

----------------

Build GlobalToken Docker container and manage with Docker Compose
----------------
Build your own local container named "globaltoken"
````
git clone https://github.com/globaltoken/globaltoken
cd globaltoken ; docker-compose build
````

Run GlobalToken in the Foreground with Docker Compose  
````
docker-compose up
````

Run GlobalToken in the Background (forever) with Docker Compose
````
docker-compose up -d
````

Deploy GlobalToken to Docker Swarm
````
docker stack deploy globaltoken_swarm
````

For more information, as well as an immediately useable, binary version of
the GlobalToken Core software, see https://globaltoken.org/#downloads, or read the
[original Bitcoin whitepaper](https://bitcoincore.org/bitcoin.pdf).

License
-------

GlobalToken Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/globaltoken/globaltoken/tags) are created
regularly to indicate new official, stable release versions of Globaltoken Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

The developer [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/bitcoin-dev)
should be used to discuss complicated or controversial changes before working
on a patch set.

Developer IRC can be found on Freenode at #bitcoin-core-dev.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and OS X, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://www.transifex.com/projects/p/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.

Translators should also subscribe to the [mailing list](https://groups.google.com/forum/#!forum/bitcoin-translators).
