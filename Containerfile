FROM ghcr.io/tcarland/tcalibcore:v24.03

USER root
WORKDIR /opt

RUN mkdir -p /opt/gktrace
COPY . /opt/gktrace

RUN cd gktrace && make

USER 1000