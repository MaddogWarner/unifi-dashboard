FROM node:22-alpine AS build
ARG APP_VERSION=0.0.0-dev
WORKDIR /app
COPY package*.json .
RUN npm ci
COPY . .
ENV VITE_APP_VERSION=$APP_VERSION
RUN npm run build

FROM nginx:alpine
RUN apk upgrade --no-cache
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx-spa.conf /etc/nginx/conf.d/default.conf
