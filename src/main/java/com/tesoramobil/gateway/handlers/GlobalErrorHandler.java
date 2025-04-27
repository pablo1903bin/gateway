package com.tesoramobil.gateway.handlers;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Maneja globalmente los errores en el Gateway.
 */
@Component
@Order(-2) // Se ejecuta antes que otros handlers
public class GlobalErrorHandler implements ErrorWebExceptionHandler {

    private final ObjectMapper objectMapper = new ObjectMapper(); // Para construir JSON fácilmente

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        final var response = exchange.getResponse();
        
        // Siempre responder en JSON
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        // Si ya se enviaron headers, no podemos hacer nada
        if (response.isCommitted()) {
            return Mono.error(ex);
        }

        // Decidir el status por defecto
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

     // Detectar tipos específicos de error para responder mejor
        if (ex instanceof org.springframework.web.server.ResponseStatusException rse) {
            status = HttpStatus.valueOf(rse.getStatusCode().value());
        } else if (ex.getMessage() != null && ex.getMessage().contains("Unauthorized")) {
            status = HttpStatus.UNAUTHORIZED;
        } else if (ex.getMessage() != null && ex.getMessage().contains("Access Denied")) {
            status = HttpStatus.FORBIDDEN;
        }

        response.setStatusCode(status);

        // Construir el JSON de respuesta
        Map<String, Object> errorAttributes = new HashMap<>();
        errorAttributes.put("timestamp", LocalDateTime.now().toString());
        errorAttributes.put("status", status.value());
        errorAttributes.put("error", status.getReasonPhrase());
        errorAttributes.put("message", ex.getMessage());
        errorAttributes.put("path", exchange.getRequest().getPath().toString());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorAttributes);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (Exception e) {
            return Mono.error(e);
        }
    }
}
