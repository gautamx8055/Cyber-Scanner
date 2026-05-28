# Dev-mode image — runs `next dev` against the volume-mounted source so edits
# on the host hot-reload inside the container. A multi-stage production build
# (build + nginx) lands in Phase 10.1.
FROM node:20-alpine

WORKDIR /app

# Install deps first, in their own layer, so a source edit doesn't bust the
# node_modules cache.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

# In dev, the rest of frontend/ is volume-mounted at /app. For production
# (Phase 10), uncomment:
# COPY frontend/ .
# RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--hostname", "0.0.0.0", "--port", "3000"]
