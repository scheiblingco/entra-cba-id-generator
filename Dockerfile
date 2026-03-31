FROM alpine:latest

ARG TARGETPLATFORM
ENTRYPOINT ["/usr/bin/entra-cbagen"]
COPY entra-cba-id-generator /usr/bin/entra-cbagen