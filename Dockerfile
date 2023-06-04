FROM kong:latest

USER root

WORKDIR /custom-plugins/kong-plugin-encryption

COPY ./kong-plugin-encryption /custom-plugins/kong-plugin-encryption

RUN apt-get update && apt-get install -y gcc libsodium-dev

RUN luarocks make

# RUN luarocks pack kong-plugin-encryption 0.0.1-1 -- Manually generated due to unknown issue, only as a temporary workaround

RUN luarocks install luasodium
RUN luarocks install kong-plugin-encryption-0.0.1-1.all.rock

RUN luarocks install redis-lua

USER kong

ENTRYPOINT [ "/docker-entrypoint.sh" ]

EXPOSE 8080 8081 8443 8444

STOPSIGNAL SIGQUIT

HEALTHCHECK --interval=10s --timeout=10s --retries=1 CMD kong health

CMD ["kong", "docker-start"]