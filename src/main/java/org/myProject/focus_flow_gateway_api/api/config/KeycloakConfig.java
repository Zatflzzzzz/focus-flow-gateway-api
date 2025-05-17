package org.myProject.focus_flow_gateway_api.api.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.PropertySource;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class KeycloakConfig {

    @Value("${KEYCLOAK_URL}")
    private String authServerUrl;

    @Value("${KEYCLOAK_REALM}")
    private String realm;

    @Value("${KEYCLOAK_CLIENT_ID}")
    private String clientId;

    @Value("${KEYCLOAK_CLIENT_SECRET}")
    private String clientSecret;
}
