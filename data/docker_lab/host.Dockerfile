FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        iproute2 \
        iputils-ping \
        nmap && \
    apt-get clean

COPY host.init.sh /init.sh
RUN chmod +x /init.sh

CMD ["/bin/bash", "/init.sh"]