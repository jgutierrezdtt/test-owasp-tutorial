// src/java/src/main/java/com/example/api/controller/XmlController.java
// PASO 6: XXE (XML External Entity) — DocumentBuilderFactory con secure processing

package com.example.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
@RestController
@RequestMapping("/api/xml")
public class XmlController {

    // VULNERABLE (punto de inicio del ejercicio):
    // @PostMapping("/parse")
    // public ResponseEntity<?> parseXml(@RequestBody String xmlInput) throws Exception {
    //     DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    //     DocumentBuilder builder = factory.newDocumentBuilder();
    //     Document doc = builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));
    //     return ResponseEntity.ok(doc.getDocumentElement().getTagName());
    // }
    //
    // Un atacante puede enviar:
    // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    // <data>&xxe;</data>
    // El servidor leera /etc/passwd y lo incluira en la respuesta.

    @PostMapping("/parse")
    public ResponseEntity<?> parseXml(@RequestBody String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));
        return ResponseEntity.ok(doc.getDocumentElement().getTagName());
    }
}
