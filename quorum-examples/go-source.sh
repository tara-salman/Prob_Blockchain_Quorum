#!/bin/bash
set -eu -o pipefail

# install build deps
add-apt-repository ppa:ethereum/ethereum
apt-get update
sudo snap install solc
apt-get install -y build-essential unzip libdb-dev libleveldb-dev libsodium-dev zlib1g-dev libtinfo-dev sysvbanner wrk software-properties-common default-jdk maven

# install golang
GOREL=go1.9.3.linux-amd64.tar.gz
wget -q https://dl.google.com/go/${GOREL}
tar xfz ${GOREL}
mv go /usr/local/go
rm -f ${GOREL}
PATH=$PATH:/usr/local/go/bin
echo 'PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.bashrc

# make/install quorum
git clone https://tarasalman:Video1234@bitbucket.org/tarasalman/probablistic-blockchain.git/
pushd probablistic-blockchain >/dev/null
make all
cp build/bin/geth /usr/local/bin
cp build/bin/bootnode /usr/local/bin
popd >/dev/null


sudo chgrp -R vagrant probablistic-blockchain
sudo chown -R vagrant probablistic-blockchain

echo 'Quorum source ready'
