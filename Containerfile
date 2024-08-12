FROM ghcr.io/tcarland/tcalibcore:v24.07.23

USER root

ENV TCAMAKE_HOME /opt/tcamake
ENV TCAMAKE_PREFIX /usr
ENV TCAMAKE_PROJECT /opt

RUN mkdir -p /opt/gktrace
COPY . /opt/gktrace

WORKDIR /opt

RUN cd gktrace && \
  source .resources/release.profile && \
  make && \
  make install

USER 1000

ENTRYPOINT ["/usr/bin/tini", "--"]