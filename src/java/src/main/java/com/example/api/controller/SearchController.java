// src/java/src/main/java/com/example/api/controller/SearchController.java
// PASO 24: XSS Reflected — escapar output HTML con HtmlUtils.htmlEscape

package com.example.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.util.HtmlUtils;

@RestController
@RequestMapping("/api/xss")
public class SearchController {

    @GetMapping("/search")
    @ResponseBody
    public String search(@RequestParam String q) {
        String safeQ = HtmlUtils.htmlEscape(q);
        return "<html><body><h2>Resultados para: " + safeQ + "</h2></body></html>";
    }
}
