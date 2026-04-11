# ---------- build ----------
FROM oven/bun:1.1 AS build
WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile
COPY . .

# ---------- runtime ----------
FROM oven/bun:1.1-slim
WORKDIR /app
COPY --from=build /app /app

VOLUME /data
EXPOSE 48349 48339

ENTRYPOINT ["bun", "run", "src/index.ts"]
CMD ["start", "--datadir=/data", "--network=testnet4"]
