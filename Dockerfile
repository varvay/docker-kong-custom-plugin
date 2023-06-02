FROM kong:latest

USER root

WORKDIR /custom-plugins/hello

COPY ./hello /custom-plugins/hello

RUN luarocks make

# RUN luarocks pack kong-plugin-hello 0.0.1-1 -- Manually generated due to unknown issue, only as a temporary workaround

RUN luarocks install kong-plugin-hello-0.0.1-1.all.rock

USER kong

ENTRYPOINT [ "/docker-entrypoint.sh" ]

EXPOSE 8080 8081 8443 8444

STOPSIGNAL SIGQUIT

HEALTHCHECK --interval=10s --timeout=10s --retries=1 CMD kong health

CMD ["kong", "docker-start", "-c", "/kong.yaml"]