package com.tesoramobil.gateway.filters;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import com.tesoramobil.gateway.dtos.TokenDto;

import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GatewayFilter {

    // Cliente Web reactivo para hacer peticiones HTTP
    private final WebClient webClient;

    // URL del endpoint que valida si el token JWT es válido
    private static final String AUTH_VALIDATE_URI = "http://localhost:3000/auth-server/auth/jwt";

    // Nombre del header donde el frontend nos manda el token JWT
    private static final String ACCESS_TOKEN_HEADER_NAME = "accessToken";

    // Constructor: construye el WebClient
    public AuthFilter() {
        this.webClient = WebClient.builder().build();
    }

    /**
     * Método que intercepta las peticiones antes de llegar al backend
     * Aquí se valida que venga un token correcto antes de dejar pasar la solicitud
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // 1. Validamos que venga el header "Authorization"
        if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return this.onError(exchange); // Si no viene, devolvemos error 400
        }

        // 2. Obtenemos el valor del header Authorization (ej: "Bearer ey...")
        final var tokenHeader = exchange
            .getRequest()
            .getHeaders()
            .get(HttpHeaders.AUTHORIZATION)
            .get(0); // toma el primer valor del header

        // 3. Separamos el contenido por espacio: ["Bearer", "el_token"]
        final var chunks = tokenHeader.split(" ");

        // 4. Validamos que tenga exactamente 2 partes y que empiece con "Bearer"
        if (chunks.length != 2 || !chunks[0].equals("Bearer")) {
            return this.onError(exchange); // Si no cumple el formato, respondemos 400
        }

        // 5. Obtenemos solo el token JWT
        final var token = chunks[1];

        // 6. Llamamos al endpoint de validación enviando el token en un header personalizado
        return this.webClient
            .post()                                       // Hacemos una petición POST
            .uri(AUTH_VALIDATE_URI)                       // Al endpoint que valida el token
            .header(ACCESS_TOKEN_HEADER_NAME, token)      // Enviamos el token en el header "accessToken"
            .retrieve()                                   // Enviamos la petición
            .bodyToMono(TokenDto.class)                   // Esperamos un TokenDto como respuesta
            .map(response -> exchange)                    // Si todo salió bien, continuamos con el request original
            .flatMap(chain::filter);                      // Dejamos pasar la petición al backend
    }

    /**
     * Método que devuelve un error 400 si el token no está presente o es inválido
     */
    private Mono<Void> onError(ServerWebExchange exchange) {
        final var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.BAD_REQUEST); // Puedes cambiarlo por UNAUTHORIZED si quieres (401)
        return response.setComplete();
    }
}
