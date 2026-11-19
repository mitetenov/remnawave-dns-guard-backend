# syntax=docker/dockerfile:1.28.0
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24 AS build
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src
RUN test "$TARGETARCH" = amd64 || (echo 'Only linux/amd64 images are supported' >&2; exit 1)
COPY go.mod go.sum ./
# Keep modules in an exported layer: GitHub's layer cache does not export cache mounts.
RUN go mod download
COPY *.go ./
COPY cmd/dns-guard ./cmd/dns-guard
RUN --mount=type=cache,id=guard-backend-go-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' -o /out/dns-guard ./cmd/dns-guard \
    && mkdir -p /out/data /out/tmp \
    && chown 10001:10001 /out/data \
    && chmod 700 /out/data \
    && chmod 1777 /out/tmp

FROM --platform=$BUILDPLATFORM alpine:3.24 AS ansible
ARG ANSIBLE_REVISION=d08132cf664ed60174292e09565342dda0e267fb
RUN apk add --no-cache ansible-core ca-certificates git
WORKDIR /opt/dns-guard/ansible
# Export only node deployment assets. The upstream inventory, vault and
# Alloy configuration belong to the operator's deployment.
RUN --mount=type=secret,id=ansible_repo_token,required=true set -eu; \
    source_dir=$(mktemp -d); \
    trap 'rm -rf "$source_dir"' EXIT; \
    git -C "$source_dir" init -q; \
    GIT_TERMINAL_PROMPT=0 git -C "$source_dir" \
        -c 'credential.helper=!f() { if [ "$1" = get ]; then printf "username=x-access-token\npassword=%s\n" "$(cat /run/secrets/ansible_repo_token)"; fi; }; f' \
        fetch -q --depth=1 https://github.com/mitetenov/ansible.git "$ANSIBLE_REVISION"; \
    git -C "$source_dir" archive -o "$source_dir/node-assets.tar" FETCH_HEAD \
        requirements.yml playbooks/nodes.yml playbooks/nodes-wl.yml \
        roles/common/defaults roles/common/files roles/common/handlers roles/common/meta roles/common/tasks roles/common/templates/sysctl \
        roles/docker roles/ssl roles/stack_nodes roles/warp_native \
        files/nodes/docker-compose.yml files/nodes/html; \
    tar -xf "$source_dir/node-assets.tar"; \
    printf '%s\n' "$ANSIBLE_REVISION" > REVISION

RUN set -eu; \
    export ANSIBLE_ROLES_PATH="$PWD/roles" ANSIBLE_COLLECTIONS_PATH="$PWD/collections"; \
    ansible-galaxy collection install --no-deps -r requirements.yml -p ./collections; \
    ansible-galaxy collection install --no-deps community.library_inventory_filtering_v1:1.1.5 -p ./collections; \
    printf '[nodes]\nexample-node ansible_connection=local\n[nodes_wl]\nexample-cdn ansible_connection=local\n' > /tmp/node-inventory; \
    ansible-playbook -i /tmp/node-inventory --syntax-check playbooks/nodes.yml; \
    ansible-playbook -i /tmp/node-inventory --syntax-check playbooks/nodes-wl.yml; \
    rm /tmp/node-inventory

FROM alpine:3.24
RUN apk add --no-cache ansible-core ca-certificates openssh-client-default openssh-keygen \
    && addgroup -S -g 10001 guard \
    && adduser -S -D -H -u 10001 -G guard guard
COPY --link --from=build --chown=10001:10001 --chmod=0700 /out/data /data
COPY --link --from=build --chmod=1777 /out/tmp /tmp
COPY --link --from=ansible /opt/dns-guard/ansible /opt/dns-guard/ansible
# The binary changes most often; stable runtime files remain independent layers.
COPY --link --from=build /out/dns-guard /dns-guard
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/dns-guard", "--healthcheck"]
ENTRYPOINT ["/dns-guard"]
