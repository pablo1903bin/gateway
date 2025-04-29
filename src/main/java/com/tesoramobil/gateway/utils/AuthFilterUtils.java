package com.tesoramobil.gateway.utils;

import java.nio.charset.StandardCharsets;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

/**
 * Utilidades comunes para la validación y procesamiento de tokens JWT en los filtros de Gateway.
 * Esta clase contiene métodos estáticos que ayudan a extraer tokens, decodificarlos y manejar errores de respuesta.
 */

public class AuthFilterUtils {

    /**
     * Extrae el token JWT del encabezado Authorization de la solicitud HTTP.
     *
     * @param exchange El intercambio actual del servidor (representa la solicitud y la respuesta).
     * @return El token JWT como String si el formato es correcto, o null si falta o es inválido.
     */
    public static String extractToken(ServerWebExchange exchange) {
        // Verifica que exista el encabezado Authorization
        if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return null; // No hay header Authorization
        }

        // Obtiene el valor del header Authorization
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // El formato esperado es: "Bearer <token>", así que hacemos split
        String[] chunks = authHeader.split(" ");
        if (chunks.length != 2 || !"Bearer".equals(chunks[0])) {
            return null; // Formato incorrecto
        }

        // Retorna el token extraído
        return chunks[1];
    }

    /**
     * Decodifica un token JWT para extraer sus Claims (los datos internos del token).
     *
     * @param token El token JWT a decodificar.
     * @param secretKey La clave secreta con la cual fue firmado el token (necesaria para validar su integridad).
     * @return Los Claims contenidos en el token (información como roles, username, fechas, etc.).
     */
    public static Claims decodeToken(String token, String secretKey) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8)) // Define la clave secreta para validar el token
                .build()
                .parseClaimsJws(token) // Parsea (valida y decodifica) el token
                .getBody(); // Extrae el cuerpo (claims) del token
    }

    /**
     * Crea una respuesta HTTP de error con un mensaje personalizado.
     * 
     * @param exchange El intercambio actual (request/response).
     * @param status El código de estado HTTP que queremos devolver (por ejemplo, 400, 401, 403).
     * @param message El mensaje de error que queremos enviar al cliente.
     * @return Un Mono<Void> que representa la escritura de la respuesta de error.
     */
    public static Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        var response = exchange.getResponse(); // Obtiene la respuesta HTTP
        response.setStatusCode(status); // Establece el código de estado (ej. 401 Unauthorized)
        
        // Crea un DataBuffer con el mensaje de error codificado en UTF-8
        DataBuffer buffer = response.bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8));
        
        // Escribe el buffer de error en la respuesta HTTP y termina la solicitud
        return response.writeWith(Mono.just(buffer));
    }
}
