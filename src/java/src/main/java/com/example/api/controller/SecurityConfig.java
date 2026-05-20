// src/java/src/main/java/com/example/api/controller/SecurityConfig.java
// PASO 10: CSRF — Spring Security con CSRF token habilitado y cookie segura

package com.example.api.controller;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // VULNERABLE (punto de inicio del ejercicio):
    // @Bean
    // public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //     http.csrf(csrf -> csrf.disable())
    //         .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    //     return http.build();
    // }
    //
    // Sin CSRF, un sitio malicioso puede hacer que el navegador del usuario
    // ejecute peticiones autenticadas (cambio de contrasena, transferencias)
    // usando las cookies de sesion existentes sin que el usuario lo sepa.

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
