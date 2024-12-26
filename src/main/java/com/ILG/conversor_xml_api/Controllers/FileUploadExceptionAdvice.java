package com.ILG.conversor_xml_api.Controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class FileUploadExceptionAdvice {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, String>> handleMaxSizeException(MaxUploadSizeExceededException exc) {
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("codeHttp", HttpStatus.PAYLOAD_TOO_LARGE.toString());
        responseMap.put("message", "Erro! O arquivo enviado é muito grande!");
        responseMap.put("Status", "Error");
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(responseMap);
    }
}

