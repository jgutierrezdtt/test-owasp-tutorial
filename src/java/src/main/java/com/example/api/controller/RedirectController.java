// src/java/src/main/java/com/example/api/controller/RedirectController.java
// PASO 7: Open Redirect — allowlist de destinos de redireccion

package com.example.api.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/auth")
public class RedirectController {

    // VULNERABLE (punto de inicio del ejercicio):
    // @GetMapping("/login")
    // public String login(@RequestParam(defaultValue = "/dashboard") String next) {
    //     return "redirect:" + next;
    // }
    //
    // Un atacante puede enviar: next=https://evil.com/phishing
    // El servidor redirige al usuario a un sitio malicioso tras el login.
    // Util para ataques de phishing y robo de credenciales.

    @GetMapping("/login")
    public String login(@RequestParam(defaultValue = "/dashboard") String next) {
        return "redirect:" + next;
    }
}
