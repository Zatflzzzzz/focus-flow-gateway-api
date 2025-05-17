package org.myProject.focus_flow_gateway_api.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    private final String[] freeResourceUrls = {
            "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**",
            "/swagger-resources/**", "/api-docs/**", "/aggregate/**", "/actuator/**",
            "/api/register/", "/api/login", "/api/refresh_token",
            "/api/register/**", "/api/login/**", "/api/refresh_token/**"
    };

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(freeResourceUrls).permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor()))
                )
                .build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("http://localhost:4200");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        return new CorsWebFilter(corsConfigurationSource());
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtGrantedAuthoritiesConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(jwtConverter);
    }

    public static class KeycloakJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(jwt);

            if (jwt.getClaims().containsKey("realm_access")) {
                Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                if (realmAccess.containsKey("roles")) {
                    Collection<String> realmRoles = (Collection<String>) realmAccess.get("roles");
                    authorities.addAll(realmRoles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toList()));
                }
            }

            if (jwt.getClaims().containsKey("resource_access")) {
                Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
                if (resourceAccess.containsKey("spring-gateway-service")) {
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get("spring-gateway-service");
                    if (clientAccess.containsKey("roles")) {
                        Collection<String> clientRoles = (Collection<String>) clientAccess.get("roles");
                        authorities.addAll(clientRoles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList()));
                    }
                }
            }

            return authorities;
        }
    }
}