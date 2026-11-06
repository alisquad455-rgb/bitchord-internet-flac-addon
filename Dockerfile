FROM node:20-alpine
WORKDIR /app
COPY package.json server.mjs manifest.json ./
ENV NODE_ENV=production
EXPOSE 8787
CMD ["npm", "start"]
