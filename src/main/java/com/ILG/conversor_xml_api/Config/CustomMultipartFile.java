package com.ILG.conversor_xml_api.Config;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

public class CustomMultipartFile implements MultipartFile {
    private final File file;
    private final String contentType; // Armazena o tipo de conteúdo

    public CustomMultipartFile(File file) {
        this.file = file;
        this.contentType = determineContentType(file); // Determina o tipo de conteúdo ao criar o objeto
    }

    private String determineContentType(File file) {
        String fileName = file.getName();
        if (fileName.endsWith(".xlsx")) {
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"; // Para arquivos XLSX
        } else if (fileName.endsWith(".xml")) {
            return "application/xml"; // Para arquivos XML
        } else {
            return "application/octet-stream"; // Tipo genérico, pode ser alterado conforme necessário
        }
    }

    @Override
    public String getName() {
        return file.getName();
    }

    @Override
    public String getOriginalFilename() {
        return file.getName();
    }

    @Override
    public String getContentType() {
        return contentType; // Retorna o tipo de conteúdo armazenado
    }

    @Override
    public boolean isEmpty() {
        return file.length() == 0;
    }

    @Override
    public long getSize() {
        return file.length();
    }

    @Override
    public byte[] getBytes() throws IOException {
        return Files.readAllBytes(file.toPath());
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new FileInputStream(file);
    }

    @Override
    public void transferTo(File dest) throws IOException, IllegalStateException {
        Files.copy(file.toPath(), dest.toPath());
    }
}
