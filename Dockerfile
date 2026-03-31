FROM alpine:latest

ARG TARGETPLATFORM
ENTRYPOINT ["/usr/bin/entra-cbagen"]
COPY $TARGETPLATFORM/entra-cba-id-generator /usr/bin/entra-cbagen