package com.ILG.conversor_xml_api.Exceptions;

import com.ILG.conversor_xml_api.Exceptions.EtAuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EtAuthException.class)
    public ResponseEntity<Map<String, String>> handleEtAuthException(EtAuthException ex) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("status", "error");
        errorResponse.put("message", ex.getMessage());
        errorResponse.put("codeHTTP", String.valueOf(HttpStatus.UNAUTHORIZED.value()));

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }
}
