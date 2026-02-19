FROM node:22-slim

WORKDIR /app

# Copy manifests
COPY package*.json ./

# Works without package-lock.json
RUN npm install --omit=dev

# Copy source
COPY . .

ENV NODE_ENV=production
EXPOSE 8080

CMD ["npm", "start"]
