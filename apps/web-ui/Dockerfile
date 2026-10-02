# SvelteKit (adapter-node) build. Unlike the Go services this one only needs
# its own directory as context — there is no shared module to resolve — so
# the context is apps/web-ui and .dockerignore's apps/web-ui exclusion (which
# keeps the frontend out of the GO builds' root context) does not apply here.
FROM node:22-alpine AS build

WORKDIR /app

# Lockfile first so the dependency layer caches independently of sources.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine

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

CMD ["node", "build"]
