# Keycloak as its production guide runs it: the build-time options fixed
# in an optimized image by kc.sh build, so that `start --optimized` does
# not rebuild at every start (which would add tens of seconds to the cold
# start the benchmark measures). README.md says what each option is for.
FROM keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3 AS builder
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_CACHE=local
RUN /opt/keycloak/bin/kc.sh build

FROM keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
