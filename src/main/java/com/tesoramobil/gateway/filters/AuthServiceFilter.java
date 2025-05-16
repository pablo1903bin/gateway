package com.tesoramobil.gateway.filters;

import com.tesoramobil.gateway.utils.AuthFilterUtils;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * Filtro para proteger las rutas del auth-service.
 * - Permite login y register sin token.
 * - Exige token válido para rutas protegidas.
 * - Valida rol ADMIN para rutas administrativas.
 */
@Component
public class AuthServiceFilter implements GatewayFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    // 🚀 Permisos para ADMIN (se usan como prefijos con startsWith)
    private static final Map<String, List<String>> adminPermisos = Map.of(
        "GET", List.of(
            "/auth-service/authentication/usuarios",
            "/auth-service/user/all"                // listar todos los usuarios
        ),
        "POST", List.of(
            "/auth-service/authentication/changerol",
            "/auth-service/user/create"
        ),
        "PUT", List.of(
            "/auth-service/user/change",
            "/auth-service/user/update"
        ),
        "DELETE", List.of(
            "/auth-service/user"                   // con path variable /user/{id}
        )
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        String method = exchange.getRequest().getMethod().name();

        System.out.println("AuthService: Solicitando acceso a: " + path + " [" + method + "]");

        // 🚪 Rutas públicas (NO requieren token)
        if (isPublicRoute(path)) {
        	System.out.println("AuthService: es ruta publica! ");
            return chain.filter(exchange); // Deja pasar
        }

        // 🔒 Rutas protegidas (requieren token)
        String token = AuthFilterUtils.extractToken(exchange);
        if (token == null) {
            return AuthFilterUtils.onError(exchange, HttpStatus.BAD_REQUEST, "Missing or invalid Authorization header.");
        }

        try {
            Claims claims = AuthFilterUtils.decodeToken(token, secretKey);
            String role = claims.get("roles", String.class);

            System.out.println("AuthService: Rol extraído del token -> " + role);

            // Validar permisos especiales de ADMIN
            if (isAdminRequiredRoute(method, path)) {
                if (!"ADMIN".equals(role)) {
                    return AuthFilterUtils.onError(exchange, HttpStatus.FORBIDDEN, "Access Denied: Only ADMIN can access this resource.");
                }
            }

            return chain.filter(exchange);

        } catch (Exception e) {
            return AuthFilterUtils.onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid or expired token.");
        }
    }

    /**
     * Verifica si la ruta es pública (no requiere autenticación).
     */
    private boolean isPublicRoute(String path) {
        return path.equals("/auth-service/authentication/sign-in") ||
               path.equals("/auth-service/authentication/sign-up");
    }

    /**
     * Verifica si esta ruta requiere que el usuario sea ADMIN.
     * Soporta rutas con variables como /user/change/{role} usando startsWith().
     */
    private boolean isAdminRequiredRoute(String method, String path) {
        return adminPermisos.getOrDefault(method, List.of())
            .stream()
            .anyMatch(path::startsWith);
    }
}
