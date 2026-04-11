FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        iproute2 \
        iptables \
        iputils-ping && \
    apt-get clean

COPY gateway.init.sh /init.sh
RUN chmod +x /init.sh

CMD ["/bin/bash", "/init.sh"]