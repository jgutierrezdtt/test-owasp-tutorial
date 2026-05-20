// src/java/src/main/java/com/example/api/controller/RedirectController.java
// PASO 7: Open Redirect — allowlist de destinos de redireccion

package com.example.api.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Set;

@Controller
@RequestMapping("/auth")
public class RedirectController {

    private static final Set<String> ALLOWED_REDIRECTS = Set.of(
        "/dashboard", "/profile", "/settings"
    );

    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam(defaultValue = "/dashboard") String next) {
        if (!ALLOWED_REDIRECTS.contains(next)) {
            return ResponseEntity.badRequest().body("Destino de redireccion no permitido");
        }
        return ResponseEntity.status(302).header("Location", next).build();
    }
}
