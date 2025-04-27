package com.tesoramobil.gateway.filters;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import com.tesoramobil.gateway.dtos.TokenDto;

import reactor.core.publisher.Mono;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;


@Component
public class AuthFilter implements GatewayFilter {

    // Cliente Web reactivo para hacer peticiones HTTP
    private final WebClient webClient;

    
    // Constructor: construye el WebClient
    public AuthFilter() {
        this.webClient = WebClient.builder().build();
    }
    
    // URL del endpoint que valida si el token JWT es válido
    private static final String AUTH_VALIDATE_URI = "http://localhost:3000/auth-server/auth/jwt";

    // Nombre del header donde el frontend nos manda el token JWT
    private static final String ACCESS_TOKEN_HEADER_NAME = "accessToken";
    
    // 🚀 Aquí estan los permisos
    private static final Map<String, Map<String, List<String>>> permisos = Map.of(
        "ADMIN", Map.of(
            "GET", List.of("/grupos-service/api/grupos/listar"),
            "POST", List.of("/grupos-service/api/grupos/crear"),
            "PUT", List.of("/grupos-service/api/grupos/modificar"),
            "DELETE", List.of("/grupos-service/api/grupos/borrar")
        ),
        "USER", Map.of(
            "GET", List.of("/grupos-service/api/grupos/listar")
        )
    );
    
	@Value("${jwt.secret}")
	private String SECRET_KEY;
	
    /**
     * Método que intercepta las peticiones antes de llegar al backend
     * Aquí se valida que venga un token correcto antes de dejar pasar la solicitud
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        
        if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return this.onError(exchange, HttpStatus.BAD_REQUEST, "Missing Authorization Header");
        }

        final var tokenHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        final var chunks = tokenHeader.split(" ");
        if (chunks.length != 2 || !chunks[0].equals("Bearer")) {
            return this.onError(exchange, HttpStatus.BAD_REQUEST, "Invalid Authorization Format");
        }

        final var token = chunks[1];

        return this.webClient
            .post()
            .uri(AUTH_VALIDATE_URI)
            .header(ACCESS_TOKEN_HEADER_NAME, token)
            .retrieve()
            .bodyToMono(TokenDto.class)
            .flatMap(response -> {
                String tokenJwt = response.getAccessToken();

                // Decodificar el token
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(SECRET_KEY.getBytes(StandardCharsets.UTF_8))
                        .build()
                        .parseClaimsJws(tokenJwt)
                        .getBody();

                String role = claims.get("roles", String.class);
                String path = exchange.getRequest().getPath().toString();
                String method = exchange.getRequest().getMethod().name();


                System.out.println("🎯 Rol extraído del token: " + role);
                System.out.println("📥 Petición a ruta: " + path + " [Método: " + method + "]");

                // 🔥 Validar permisos basado en nuestro Map
                if (!isAuthorized(role, method, path)) {
                    return this.onError(exchange, HttpStatus.FORBIDDEN, "Access Denied: You don't have permission.");
                }

                // Si todo bien, deja pasar
                return chain.filter(exchange);
            })   .onErrorResume(error -> {
                // 🔥 Si hubo error en la validación, respondemos 401 al cliente
                return this.onError(exchange, HttpStatus.UNAUTHORIZED, "Token inválido o expirado.");
            });
    }
    
    private boolean isAuthorized(String role, String method, String path) {
        return permisos.getOrDefault(role, Map.of())
            .getOrDefault(method, List.of())
            .stream()
            .anyMatch(allowedPath -> allowedPath.equals(path));
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        final var response = exchange.getResponse();
        response.setStatusCode(status);
        DataBuffer buffer = response.bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
    
}
