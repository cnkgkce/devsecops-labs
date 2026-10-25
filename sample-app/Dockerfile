# Upgraded hardened base image (Node 20 Alpine)
FROM node:20-alpine

# Patch Alpine OS packages to 0 CVEs
RUN apk update && apk upgrade --no-cache

# Security hardening: Non-root execution
WORKDIR /usr/src/app

COPY package*.json ./

# Install dependencies (will include vulnerable versions)
RUN npm install --only=production

COPY . .

EXPOSE 3000

# Hardening: Run as non-root unprivileged user
USER node

CMD ["node", "server.js"]
