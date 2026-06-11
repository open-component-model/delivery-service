FROM golang:alpine AS cbomkit-theia-builder

ARG CBOMKIT_THEIA_VERSION=1.0.1

RUN apk add --no-cache git \
&& git clone --branch ${CBOMKIT_THEIA_VERSION} https://github.com/IBM/cbomkit-theia.git /cbomkit-theia \
&& cd /cbomkit-theia \
&& go mod download \
&& go build

FROM alpine:3

COPY clamav_entrypoint.sh /
COPY clamd.conf /etc/clamav/clamd.conf
COPY --from=cbomkit-theia-builder /cbomkit-theia/cbomkit-theia /usr/bin/cbomkit-theia

RUN --mount=type=bind,source=/dist,target=/dist \
    apk add --no-cache \
    bash \
    ca-certificates \
    clamav \
    clamav-libunrar \
    curl \
    gcc \
    git \
    helm \
    libc-dev \
    libffi-dev \
    postgresql16-client \
    python3 \
    python3-dev \
    py3-numpy \
    py3-pip \
    py3-scipy \
    syft \
&& curl https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt -o \
    /usr/local/share/ca-certificates/SAP_Global_Root_CA.crt \
&& curl https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt -o \
    /usr/local/share/ca-certificates/SAPNetCA_G2_2.crt \
&& update-ca-certificates \
&& mkdir -p $HOME/.config/pip \
&& echo -e "[global]\nbreak-system-packages = true" >> $HOME/.config/pip/pip.conf \
&& pip3 install --upgrade --no-cache-dir --find-links ./dist odg-core-libs \
&& apk del --no-cache \
    libc-dev \
    libffi-dev \
    python3-dev \
&& ln -sf /etc/ssl/certs/ca-certificates.crt "$(python3 -m certifi)" \
&& mkdir /freshclam \
&& chown clamav /freshclam
