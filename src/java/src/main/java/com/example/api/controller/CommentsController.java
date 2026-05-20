// src/java/src/main/java/com/example/api/controller/CommentsController.java
// PASO 25: XSS Stored — escapar contenido almacenado al renderizarlo en HTML

package com.example.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/comments")
public class CommentsController {

    private final List<String> comments = new ArrayList<>();

    // VULNERABLE (punto de inicio del ejercicio):
    // @GetMapping
    // @ResponseBody
    // public String getComments() {
    //     StringBuilder sb = new StringBuilder("<ul>");
    //     for (String c : comments) {
    //         sb.append("<li>").append(c).append("</li>");
    //     }
    //     sb.append("</ul>");
    //     return sb.toString();
    // }
    //
    // El comentario se almacena con <script>alert(1)</script> y se devuelve sin escapar.
    // El XSS stored es mas peligroso que el reflected: el payload se ejecuta para TODOS
    // los usuarios que visiten la pagina, no solo quien sigue un enlace especial.
    // Un atacante puede inyectar un keylogger o un script de phishing persistente.

    @PostMapping
    public ResponseEntity<?> addComment(@RequestBody Map<String, String> body) {
        String comment = body.get("comment");
        if (comment == null || comment.isBlank()) {
            return ResponseEntity.badRequest().body("Comentario vacio");
        }
        comments.add(comment);
        return ResponseEntity.ok().build();
    }

import org.springframework.web.util.HtmlUtils;

    @GetMapping
    @ResponseBody
    public String getComments() {
        StringBuilder sb = new StringBuilder("<ul>");
        for (String c : comments) {
            sb.append("<li>").append(HtmlUtils.htmlEscape(c)).append("</li>");
        }
        sb.append("</ul>");
        return sb.toString();
    }
}
