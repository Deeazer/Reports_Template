FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY styles.css /usr/share/nginx/html/styles.css
COPY js /usr/share/nginx/html/js
COPY img /usr/share/nginx/html/img
COPY vendor /usr/share/nginx/html/vendor

EXPOSE 80
