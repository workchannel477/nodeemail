FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production

COPY package*.json ./
COPY scripts ./scripts
RUN npm ci --omit=dev

COPY api ./api
COPY public ./public

RUN npm run build

COPY data ./data

EXPOSE 5000

CMD ["node", "api/server.js"]
