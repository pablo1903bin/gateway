package com.tesoramobil.gateway.beans;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.tesoramobil.gateway.filters.AuthServiceFilter;
import com.tesoramobil.gateway.filters.GruposServiceFilter;

@Configuration // Esta clase contiene beans de configuración para el Gateway
public class GatewayRoutesConfigBean {

    @Autowired
    AuthServiceFilter authFilter; 

    @Autowired
    GruposServiceFilter gruposServiceFilter;
    // 🔌 Rutas locales SIN Eureka
    @Bean
    @Profile("eureka-off") // Este bean solo se activa cuando el perfil "eureka-off" está activo
    public RouteLocator routeLocatorEurekaOff(RouteLocatorBuilder builder) {
        System.out.println("🚧 Configurando rutas SIN Eureka");

        return builder.routes()

            // Ruta hacia auth-service en localhost:8082
            .route("auth-service", r -> r
                .path("/gateway/auth-service/authentication/**") // Si la ruta coincide con esto...
                .filters(f -> f.stripPrefix(1)) // Le quitamos el prefijo "/gateway"
                .uri("http://localhost:8082")) // Redirigimos a este servicio directamente

            // Ruta hacia grupos-service en localhost:8081
            .route("grupos-service", r -> r
                .path("/gateway/grupos-service/api/grupos/**")
                .filters(f -> f.stripPrefix(1))
                .uri("http://localhost:8081"))

            .build();
    }

    // ☁️ Rutas usando Eureka
    @Bean
    @Profile("eureka-on") // Este bean se activa con el perfil "eureka-on"
    public RouteLocator routeLocatorEurekaOn(RouteLocatorBuilder builder) {
        System.out.println("☁️ Configurando rutas CON Eureka");

        return builder.routes()

            // Ruta hacia auth-service registrado en Eureka
            .route("auth-service", r -> r
                .path("/gateway/auth-service/authentication/**")
                .filters(f -> f.stripPrefix(1))
                .uri("lb://auth-service")) // lb:// significa "load-balanced", busca en Eureka

            // Ruta hacia grupos-service registrado en Eureka
            .route("grupos-service", r -> r
                .path("/gateway/grupos-service/api/grupos/**")
                .filters(f -> f.stripPrefix(1))
                .uri("lb://grupos-service"))

            .build();
    }

    // 🔐 Rutas seguras con perfil OAUTH2 (autenticación + validación de token)
    @Bean
    @Profile("oauth2") // Solo se activa cuando el perfil es "oauth2"
    RouteLocator routeLocatorOauth2(RouteLocatorBuilder builder) {
        System.out.println("🔐 Configurando rutas seguras con perfil OAUTH2");

        return builder
            .routes()

            // 🔐 auth-service protegido con authFilter
            .route("auth-service", route -> route
            	.path("/gateway/auth-service/**")
                .filters(filter -> filter
                    .stripPrefix(1) 
                    .filter(this.authFilter)
                )
                .uri("lb://auth-service") // se busca en Eureka
            )

            // 🔐 grupos-service protegido también
            .route("grupos-service", route -> route
                .path("/gateway/grupos-service/api/grupos/**")
                .filters(filter -> {
                    filter.stripPrefix(1);
                    filter.filter(this.gruposServiceFilter);
                    return filter;
                })
                .uri("lb://grupos-service")
            )

            // 📥 auth-server no requiere filtro (acá se hace el login, generación de token, etc.)
            .route("auth-server", route -> route
            	    .path("/auth-server/auth/**")
            	    .uri("lb://auth-server")
            	)
            .build();
    }
}
