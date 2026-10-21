FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Réseau qui intercepte TLS : NPM_STRICT_SSL=false dans .env, voir README. Vérification activée par défaut.
ARG NPM_STRICT_SSL=true
RUN npm config set strict-ssl ${NPM_STRICT_SSL} && (npm ci || npm install)
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
