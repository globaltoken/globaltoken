# Maintained by Crypto and Coffee | https://cryptoandcoffee.com
FROM ubuntu:16.04
COPY ./build-docker.sh ./build-docker.sh
RUN ./build-docker.sh ; rm build-docker.sh
CMD globaltokend -printtoconsole