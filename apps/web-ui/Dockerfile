# SvelteKit (adapter-node) build. Unlike the Go services this one only needs
# its own directory as context — there is no shared module to resolve — so
# the context is apps/web-ui and .dockerignore's apps/web-ui exclusion (which
# keeps the frontend out of the GO builds' root context) does not apply here.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build

WORKDIR /app

# Lockfile first so the dependency layer caches independently of sources.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5

WORKDIR /app

# adapter-node needs the built output plus production dependencies.
COPY --from=build /app/build ./build
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# node:alpine ships an unprivileged `node` user (uid 1000).
USER node

# The same unauthenticated /healthz the Kubernetes probes use (503 while the
# UI is unconfigured). BusyBox wget rather than a second node process: the
# lite profile caps this container at 128 MiB. Kubernetes ignores HEALTHCHECK.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-3000}/healthz" || exit 1

CMD ["node", "build"]
