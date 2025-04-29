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

@Component
public class GruposServiceFilter implements GatewayFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    private static final Map<String, Map<String, List<String>>> permisos = Map.of(
        "ADMIN", Map.of(
            "GET", List.of("/grupos-service/api/grupos/listar"),
            "POST", List.of("/grupos-service/api/grupos/crear"),
            "PUT", List.of("/grupos-service/api/grupos/modificar"),
            "DELETE", List.of("/grupos-service/api/grupos/borrar")
        ),
        "USER", Map.of(
            "GET", List.of("/grupos-service/api/grupos/grupo")
        )
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("🚨 [GruposServiceFilter] Iniciando validación de token...");

        String token = AuthFilterUtils.extractToken(exchange);
        if (token == null) {
            System.out.println("❌ No se encontró token válido en el header Authorization.");
            return AuthFilterUtils.onError(exchange, HttpStatus.BAD_REQUEST, "Missing or invalid Authorization header.");
        }

        System.out.println("✅ Token recibido: " + token);
        System.out.println("🔐 Clave secreta (JWT): " + secretKey);

        try {
            Claims claims = AuthFilterUtils.decodeToken(token, secretKey);
            String role = claims.get("roles", String.class);
            System.out.println("✅ Rol recibido: " + role);
            String path = exchange.getRequest().getPath().toString();
            String method = exchange.getRequest().getMethod().name();

            System.out.println("✅ Token decodificado correctamente.");
            System.out.println("👤 Rol extraído: " + role);
            System.out.println("📥 Petición entrante: " + method + " -> " + path);

            if (!isAuthorized(role, method, path)) {
                System.out.println("⛔ Rol " + role + " no tiene permiso para acceder a " + method + " " + path);
                return AuthFilterUtils.onError(exchange, HttpStatus.FORBIDDEN, "Access Denied: You don't have permission for grupos-service.");
            }

            System.out.println("✅ Acceso autorizado, continuando con la petición.");
            return chain.filter(exchange);

        } catch (Exception e) {
            System.out.println("❌ Error al decodificar token: " + e.getMessage());
            return AuthFilterUtils.onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid or expired token.");
        }
    }

    private boolean isAuthorized(String role, String method, String path) {
        return permisos.getOrDefault(role, Map.of())
            .getOrDefault(method, List.of())
            .stream()
            .anyMatch(path::equals);
    }
}
