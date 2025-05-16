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
    	        "GET", List.of(
    	            "/grupos-service/grupos/listar",
    	            "/grupos-service/grupos/grupos-por-rol", // nueva ruta dinámica
    	            "/grupos-service/grupos"                 // para posibles otras rutas GET
    	        ),
    	        "POST", List.of(
    	            "/grupos-service/grupos/crear"
    	        ),
    	        "PUT", List.of(
    	            "/grupos-service/grupos/modificar"
    	        ),
    	        "DELETE", List.of(
    	            "/grupos-service/grupos/borrar"
    	        )
    	    ),
    	    "USER", Map.of(
    	        "GET", List.of(
    	            "/grupos-service/grupos/grupo",
    	            "/grupos-service/grupos/grupos-por-rol" // permitir acceso parcial a usuarios también
    	        )
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
            Long userIdFromToken = claims.get("id", Long.class); // ⬅️ Extrae el ID desde el token

            String path = exchange.getRequest().getPath().toString();
            String method = exchange.getRequest().getMethod().name();

            System.out.println("✅ Token decodificado correctamente.");
            System.out.println("👤 Rol extraído: " + role);
            System.out.println("🆔 ID desde token: " + userIdFromToken);
            System.out.println("📥 Petición entrante: " + method + " -> " + path);

            // 🔐 Validación específica para /grupos-por-rol/{id}
            if (path.startsWith("/grupos-service/grupos/grupos-por-rol/")) {
                String idInPath = path.substring(path.lastIndexOf("/") + 1);
                try {
                    Long requestedId = Long.parseLong(idInPath);
                    if (!userIdFromToken.equals(requestedId)) {
                        System.out.println("⛔ Acceso denegado: el ID en la URL no coincide con el del token.");
                        return AuthFilterUtils.onError(exchange, HttpStatus.FORBIDDEN, "Access Denied: Cannot access data from another user.");
                    }
                } catch (NumberFormatException ex) {
                    return AuthFilterUtils.onError(exchange, HttpStatus.BAD_REQUEST, "Invalid user ID in path.");
                }
            }

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
            .anyMatch(path::startsWith); // usar startsWith en vez de equals
    }

}
