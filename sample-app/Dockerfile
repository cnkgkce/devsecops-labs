# Intentionally using an older base image to demonstrate container vulnerability detection with Trivy
FROM node:16.14.0-alpine

# Security misconfiguration demo: Running as root by default
WORKDIR /usr/src/app

COPY package*.json ./

# Install dependencies (will include vulnerable versions)
RUN npm install --only=production

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
