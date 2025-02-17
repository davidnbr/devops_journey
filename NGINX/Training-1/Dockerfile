FROM nginx:stable

COPY .env /etc/nginx/.env
COPY ./default.conf.template /etc/nginx/conf.d/default.conf.template
COPY ./nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /usr/share/nginx/html
COPY ./nginx/static /usr/share/nginx/html

RUN mkdir -p /etc/nginx/ssl
COPY nginx-selfsigned.crt /etc/nginx/ssl/nginx-selfsigned.crt
COPY nginx-selfsigned.key /etc/nginx/ssl/nginx-selfsigned.key

EXPOSE 80 443 8081 8082

CMD ["nginx", "-g", "daemon off;"]
