# SvelteKit (adapter-node) build. Unlike the Go services this one only needs
# its own directory as context — there is no shared module to resolve — so
# the context is apps/web-ui and .dockerignore's apps/web-ui exclusion (which
# keeps the frontend out of the GO builds' root context) does not apply here.
#
# Both build stages run on the build platform: adapter-node's output is
# JavaScript, the same for every architecture, so an arm64 image needs no
# emulator for the npm installs and the build. That holds only while the
# production dependencies contain no native addon (today there are no
# production dependencies at all); the build fails if one appears, because
# it would be built for the wrong architecture here.
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build

WORKDIR /app

# Lockfile first so the dependency layer caches independently of sources.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

# Production dependencies installed from the lockfile on their own, rather
# than pruned out of the build's tree (deleting the dev tree is the slow
# part of a build, and this layer caches across source changes).
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && mkdir -p node_modules \
    && if [ -n "$(find node_modules -name '*.node' -print -quit)" ]; then \
         echo "a production dependency ships a native addon; build it on the target platform" >&2; \
         exit 1; \
       fi

FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5

# The server runs `node build` and nothing else: the package managers the
# base image ships (npm with its own dependency tree, and on older Node
# lines corepack and yarn) are removed, and Alpine's security updates are
# applied (the weekly rebuild picks them up between base-image bumps).
RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules /opt/yarn-* \
         /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
         /usr/local/bin/yarn /usr/local/bin/yarnpkg

WORKDIR /app

# adapter-node needs the built output plus production dependencies.
COPY --from=build /app/build ./build
COPY --from=deps /app/node_modules ./node_modules
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
