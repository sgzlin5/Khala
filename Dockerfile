FROM debian:12 AS base

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources
RUN apt update && \
    apt -y install \
    build-essential \
    libjson-c-dev \
    libcurl4-openssl-dev \
    cmake


FROM base AS build

WORKDIR /
COPY . /khala
RUN cd /khala && mkdir build && cd build && cmake .. && make && cp ./supernode /bin/


FROM build AS run

ENV PORT=7654
ENV FEDERATION=Ruijie
ENV AUTH_URL="http://10.51.133.99:8100/base/n2n/vnp/auth"

EXPOSE 7654

CMD ["sh", "-c", "/bin/supernode -F $FEDERATION -p $PORT -s $AUTH_URL -f"]
