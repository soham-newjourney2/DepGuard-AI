# Disposable verification worker: resolves and tests a copied workspace, never the API host.
FROM node:20.19.6-bookworm-slim@sha256:b342de02eb4a57cd6986290a69833d20818508db8078dba0197a024193410aee

ENV CI=true \
    npm_config_cache=/tmp/.npm \
    npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false \
    npm_config_ignore_scripts=true

COPY --chmod=0555 entry.sh /usr/local/bin/depguard-entry

USER node
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/depguard-entry"]
