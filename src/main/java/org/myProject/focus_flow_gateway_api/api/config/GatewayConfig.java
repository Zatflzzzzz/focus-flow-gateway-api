package org.myProject.focus_flow_gateway_api.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.WebFilter;

@Configuration
public class GatewayConfig {

    @Bean
    public WebFilter forwardAuthTokenFilter() {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                exchange = exchange.mutate()
                        .request(builder -> builder.header("Authorization", authHeader))
                        .build();
            }
            return chain.filter(exchange);
        };
    }
}