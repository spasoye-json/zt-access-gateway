# ------------------------
# Builder stage
# ------------------------
FROM node:18-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY src ./src
COPY policy ./policy
COPY nest-cli.json tsconfig.json ./

RUN npm run build


# ------------------------
# Runtime stage
# ------------------------
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/policy ./policy

RUN addgroup -g 1001 -S nodejs \
 && adduser -S nestjs -u 1001

USER nestjs

EXPOSE 3000

CMD ["node", "dist/main.js"]
