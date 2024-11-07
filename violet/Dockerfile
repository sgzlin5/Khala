FROM debian:12 as base

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources
RUN apt update && \
    apt -y install \
    build-essential \
    cmake

FROM base as build

WORKDIR /
COPY ./lib/libjuice /khala/lib/libjuice
COPY ./violet /khala/violet
RUN cd /khala/violet; \
    cmake -B build -DCMAKE_BUILD_TYPE=Release; \
    cd build; \
    make; \
    cp ./violet /bin/

FROM build as run

ENV PORT=$PORT

EXPOSE $PORT

CMD ["sh", "-c", "/bin/violet --credentials=khala:khala  --port=$PORT"]
