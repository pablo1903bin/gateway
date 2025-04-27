package com.tesoramobil.gateway.dtos;


public enum Role {
    /**
     * Rol básico para usuarios estándar.
     * Los usuarios con este rol tienen permisos limitados.
     */
    USER,

    /**
     * Rol para administradores.
     * Los usuarios con este rol tienen acceso completo a las funcionalidades del sistema.
     */
    ADMIN
}
