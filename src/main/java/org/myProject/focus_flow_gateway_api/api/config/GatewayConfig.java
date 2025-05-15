package org.myProject.focus_flow_gateway_api.api.config;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
public class GatewayConfig {
    GatewayRoutesProperties gatewayRoutesProperties;

    @Bean
    public RouterFunction<ServerResponse> fallBackRoute() {
        return org.springframework.web.reactive.function.server.RouterFunctions.route()
                .GET("/fallbackRoute", request ->
                        ServerResponse.status(HttpStatus.SERVICE_UNAVAILABLE)
                                .bodyValue("Service unavailable, please try again later"))
                .build();
    }

    @Bean
    public RouteLocator staticRoutes(RouteLocatorBuilder builder) {
        RouteLocatorBuilder.Builder routes = builder.routes();
        List<GatewayRoutesProperties.Route> routeConfigs = gatewayRoutesProperties.getRoutes();

        for (GatewayRoutesProperties.Route configRoute : routeConfigs) {
            routes.route(configRoute.getId(), r -> r.path(configRoute.getPredicates().get(0))
                    .filters(f -> f.circuitBreaker(c -> c.setName(configRoute.getId() + "Breaker")
                                    .setFallbackUri("forward:/fallbackRoute"))
                            .uri(configRoute.getUri()));
        }

        return routes.build();
    }
}