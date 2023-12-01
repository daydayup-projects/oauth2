package tech.alexchen.daydayup.oauth2.client.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    RouteLocator gateway(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(rs -> rs.path("/admin/**")
                        .filters(f -> f.stripPrefix(1).tokenRelay())
                        .uri("http://127.0.0.1:8080")
                )
                .build();
    }
}
