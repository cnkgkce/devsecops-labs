# Stage 1: Build React frontend with Vite
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Production runtime with lightweight Express server
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --only=production

COPY --from=builder /app/dist ./dist
COPY server.js ./

EXPOSE 3001
ENV PORT=3001
ENV REPORTS_DIR=/app/reports

CMD ["node", "server.js"]
