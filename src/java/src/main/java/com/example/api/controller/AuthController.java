// src/java/src/main/java/com/example/api/controller/AuthController.java
// PASO 9: Log Injection — sanitizar input antes de escribirlo en logs

package com.example.api.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    // VULNERABLE (punto de inicio del ejercicio):
    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestParam String username,
    //                                @RequestParam String password) {
    //     log.info("Login attempt for user: " + username);
    //     ...
    // }
    //
    // Un atacante puede enviar: username=admin\nINFO: Login successful for user: admin
    // Esto inyecta una linea falsa en los logs que puede confundir a analistas
    // o sistemas SIEM, ocultando actividad maliciosa real.

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username,
                                   @RequestParam String password) {
        log.info("Login attempt for user: " + username);
        // autenticar usuario...
        return ResponseEntity.ok(Map.of("message", "OK"));
    }
}
