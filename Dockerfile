ARG BUILDER_IMAGE=golang:1.17-buster
ARG BASE_IMAGE=alpine:3.15

FROM ${BUILDER_IMAGE} AS build-stage

ENV CGO_ENABLED=0

WORKDIR /src
COPY . .

RUN go mod download
RUN go build

# Final Docker image
FROM ${BASE_IMAGE} AS final-stage
LABEL MAINTAINER "Thomas Labarussias <issif+falco-talon@gadz.org>"

RUN apk add --update --no-cache ca-certificates

# Create user falcotalon
RUN addgroup -S falcotalon && adduser -u 1234 -S falcotalon -G falcotalon
# must be numeric to work with Pod Security Policies:
# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
USER 1234

WORKDIR ${HOME}/app
COPY --from=build-stage /src/LICENSE .
COPY --from=build-stage /src/falco-talon .

EXPOSE 2803

ENTRYPOINT ["./falco-talon"]