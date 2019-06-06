# Maintained by Crypto and Coffee | https://cryptoandcoffee.com
#Docker uses this file internally to build GlobalToken for Ubuntu 16.04.  This code is portable for other Ubuntu/Debian usage.
#Setup dependencies
echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
apt-get update && apt-get install -y software-properties-common git build-essential curl zlib1g-dev autotools-dev automake libtool pkg-config wget libsodium-dev libboost-all-dev bsdmainutils libssl-dev libevent-dev libzmq3-dev
git clone https://github.com/globaltoken/globaltoken globaltoken
cd globaltoken/depends ; make HOST=x86_64-linux-gnu -j$(nproc) ; cd ..

#Install Berkley DB
BITCOIN_ROOT=$(pwd) ; BDB_PREFIX="${BITCOIN_ROOT}/db4" ; mkdir -p $BDB_PREFIX
wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz' ; echo '12edc0df75bf9abd7f82f821795bcee50f42cb2e5f76a6a281b85732798364ef db-4.8.30.NC.tar.gz' | sha256sum -c
tar -xzvf db-4.8.30.NC.tar.gz ; cd db-4.8.30.NC/build_unix/ ; ../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
make install ; cd $BITCOIN_ROOT

# Install GlobalToken
make ; make install ; ./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-linux-gnu/share/config.site ./configure LDFLAGS="-L${BDB_PREFIX}/lib/" CPPFLAGS="-I${BDB_PREFIX}/include/" --prefix=$PWD/depends/x86_64-linux-gnu --enable-debug
make -j$(nproc)

# Move files into place
strip src/globaltokend
strip src/globaltoken-cli
strip src/globaltoken-tx
cp src/globaltoken-cli /usr/bin/
cp src/globaltokend /usr/bin/
cp src/globaltoken-tx /usr/bin/

cd .. ; rm -rf globaltoken ; rm -rf /var/lib/apt/lists/* ; mkdir -p /root/.globaltoken/

#Generate random logins
#USER=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64 ; echo '')
#PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64 ; echo '')

cat <<EOT >> /root/.globaltoken/globaltoken.conf
#user=$USER
#pass=$PASS
acceptdividedcoinbase=1 #required for mining
algo=sha256d
EOT
