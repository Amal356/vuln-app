# syntax=docker/dockerfile:1
# Dockerfile corrigé : image récente, multi-stage, dépendances de prod uniquement, non-root, sans secret.

# ---------- Étape 1 : dépendances (outils de compilation seulement ici) ----------
FROM node:25-alpine AS deps
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ---------- Étape 2 : runtime minimal ----------
FROM node:25-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- "http://localhost:3000/hello?name=healthcheck" || exit 1
# Les secrets (JWT_SECRET, PAYMENT_API_KEY, DB_PASSWORD) sont fournis au lancement : docker run --env-file .env
CMD ["node", "src/server.js"]
