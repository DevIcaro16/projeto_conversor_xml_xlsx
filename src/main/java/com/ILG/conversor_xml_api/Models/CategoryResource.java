package com.ILG.conversor_xml_api.Models;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/arquivos")
public class CategoryResource {

    @GetMapping("")
    public ResponseEntity<Map<String, String>> getAllCategories(HttpServletRequest req) {
        Integer id = (Integer) req.getAttribute("id");

        if (id == null) {
            Map<String, String> errorMap = new HashMap<>();
            errorMap.put("codeHttp  ", HttpStatus.UNAUTHORIZED.toString());
            errorMap.put("message", "Token inválido ou não fornecido!");
            errorMap.put("Status", "Error!");
            return new ResponseEntity<>(errorMap, HttpStatus.UNAUTHORIZED);
        }

        Map<String, String> map = new HashMap<>();
        map.put("codeHttp", HttpStatus.OK.toString());
        map.put("message", "Usuário com Token Autorizado! ID: " + id);
        map.put("Status", "Success!");

        return new ResponseEntity<>(map, HttpStatus.OK);
    }



}
