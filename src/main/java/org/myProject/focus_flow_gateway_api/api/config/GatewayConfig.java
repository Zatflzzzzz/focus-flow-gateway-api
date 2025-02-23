package org.myProject.focus_flow_gateway_api.api.config;

import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.*;

@Configuration
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class GatewayConfig {

    GatewayRoutesProperties gatewayRoutesProperties;

    @Autowired
    public GatewayConfig(GatewayRoutesProperties gatewayRoutesProperties) {

        this.gatewayRoutesProperties = gatewayRoutesProperties;
    }

    @Bean
    public RouterFunction<ServerResponse> dynamicRoutes() {

        RouterFunction<ServerResponse> route = GatewayRouterFunctions.route()
                .route(RequestPredicates.path("/api/task-service/**"), HandlerFunctions.http("http://localhost:8080"))
                .build();

        for (GatewayRoutesProperties.Route configRoute : gatewayRoutesProperties.getRoutes()) {

            route = GatewayRouterFunctions.route()
                    .add(route)
                    .route(RequestPredicates.path(configRoute.getPredicates().get(0)),
                            HandlerFunctions.http(configRoute.getUri()))
                    .build();
        }

        return route;
    }


}
