# nginx/Dockerfile
FROM nginx:alpine

# Usuwamy domyslna konfig
RUN rm /etc/nginx/conf.d/default.conf

# kopiujemy nasz konfig 
COPY nginx.conf /etc/nginx/conf.d/default.conf

# kopiujemy certyfikaty z certs
COPY certs/ /etc/nginx/ssl/