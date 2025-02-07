package org.myProject.focus_flow_gateway_api.api.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "spring.cloud.gateway.mvc")
@Data
public class GatewayRoutesProperties {

    private List<Route> routes = new ArrayList<>();

    @Data
    public static class Route {
        private String id;
        private String uri;
        private List<String> predicates;
        private List<String> filters;

    }
}