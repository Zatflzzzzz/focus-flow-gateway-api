package org.myProject.focus_flow_gateway_api.api.config;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.cloud.gateway.server.mvc.filter.CircuitBreakerFilterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.function.*;

import java.net.URI;
import java.util.List;

@Configuration
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
public class GatewayConfig {

    GatewayRoutesProperties gatewayRoutesProperties;

    @Bean
    public RouterFunction<ServerResponse> fallBackRoute() {
        return RouterFunctions.route()
                .GET("/fallbackRoute", request ->
                        ServerResponse.status(HttpStatus.SERVICE_UNAVAILABLE)
                                .body("Service unavailable, please try again later"))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> staticRoutes() {
        RouterFunction<ServerResponse> route = RouterFunctions.route()
                .GET("/api/task-service/**", HandlerFunctions.http("http://localhost:8080"))
                .build();

        List<GatewayRoutesProperties.Route> routeConfigs = gatewayRoutesProperties.getRoutes();
        for (GatewayRoutesProperties.Route configRoute : routeConfigs) {
            route = route.and(
                    RouterFunctions.route(
                                    RequestPredicates.path(configRoute.getPredicates().get(0)),
                                    HandlerFunctions.http(configRoute.getUri())
                            )
                            .filter(CircuitBreakerFilterFunctions.circuitBreaker(
                                    configRoute.getId() + "Breaker",
                                    URI.create("forward:/fallbackRoute")
                            ))
            );
        }

        return route;
    }
}