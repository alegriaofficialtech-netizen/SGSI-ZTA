FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM caddy:2-alpine
# High port 8080 needs no file capability; remove it before dropping all caps.
RUN setcap -r /usr/bin/caddy
COPY --chown=10001:10001 --chmod=0444 Caddyfile /etc/caddy/Caddyfile
COPY --chown=10001:10001 --chmod=0444 DemoCaddyfile /etc/caddy/DemoCaddyfile
COPY --from=build --chown=10001:10001 /app/dist /srv
EXPOSE 8080
