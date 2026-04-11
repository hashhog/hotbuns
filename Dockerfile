# ---------- build ----------
FROM oven/bun:1.2 AS build
WORKDIR /app
COPY package.json bun.lock* ./
# Install dependencies; zeromq uses a native postinstall script that may
# fail on some CPU configurations.  If it does, fall back to installing
# without lifecycle scripts so the image still builds.
RUN bun install --frozen-lockfile || \
    (echo "Retrying with --ignore-scripts for native packages" && \
     bun install --frozen-lockfile --ignore-scripts)
COPY . .

# ---------- runtime ----------
FROM oven/bun:1.2-slim
WORKDIR /app
COPY --from=build /app /app

VOLUME /data
EXPOSE 48349 48339

ENTRYPOINT ["bun", "run", "src/index.ts"]
CMD ["start", "--datadir=/data", "--network=testnet4"]
