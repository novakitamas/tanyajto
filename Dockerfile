FROM node:22-alpine

ENV NODE_ENV=production \
    AUTH_DIR=/data

WORKDIR /app

COPY toggle-bot.mjs secret-codec.mjs ./

# Saved accounts, tokens and the encryption key live in /data (a volume).
RUN mkdir -p /data && chown -R node:node /data /app

USER node

VOLUME ["/data"]

CMD ["node", "toggle-bot.mjs"]
