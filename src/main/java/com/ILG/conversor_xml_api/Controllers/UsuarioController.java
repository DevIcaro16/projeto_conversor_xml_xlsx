package com.ILG.conversor_xml_api.Controllers;

import com.ILG.conversor_xml_api.Exceptions.EtAuthException;
import com.ILG.conversor_xml_api.Filters.AuthFilter;
import com.ILG.conversor_xml_api.Interfaces.UsuarioInterface;
import com.ILG.conversor_xml_api.Interfaces.UsuarioInterfaceImpl;
import com.ILG.conversor_xml_api.Config.constants;
import com.ILG.conversor_xml_api.Models.UsuarioModel;

import javax.crypto.SecretKey;

import com.ILG.conversor_xml_api.Repositories.UsuarioRepository;
import com.fasterxml.jackson.core.JsonPointer;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.sql.Date;
import java.text.ParseException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    private final UsuarioInterfaceImpl usuarioInterfaceImpl;

    @Autowired
    UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UsuarioController(UsuarioInterfaceImpl usuarioInterfaceImpl) {
        this.usuarioInterfaceImpl = usuarioInterfaceImpl;
    }

    @Autowired
    UsuarioInterface usuarioInterface;


    @PostMapping("/registro")
    public ResponseEntity<Map<String, String>> registroUsuario(@RequestBody Map<String, Object> usuarioMap) throws ParseException {

        String login = (String) usuarioMap.get("login");

        String nome = (String) usuarioMap.get("nome");

        String senha = (String) usuarioMap.get("senha");

        String dataNascimento = (String) usuarioMap.get("dataNascimento");

        String cpf = (String) usuarioMap.get("cpf");

        String[] arrDados = new String[5];

        arrDados[0] = login;
        arrDados[1] = nome;
        arrDados[2] = senha;
        arrDados[3] = dataNascimento;
        arrDados[4] = cpf;

        String msgErroDados = null;

        for (int i = 0; i < arrDados.length; i++) {
            msgErroDados = "";

            if (arrDados[i] == null) {
                msgErroDados += arrDados[i] + ", ";
            }

        }

        System.out.println(msgErroDados);

        String nivel = "1";

        // Conversão da string de data para LocalDate usando o formato esperado
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy"); // ajuste o formato conforme necessário
        LocalDate localDate = LocalDate.parse(dataNascimento, formatter);

        // Converte LocalDate para java.sql.Date
        java.sql.Date sqlDate = java.sql.Date.valueOf(localDate);

        UsuarioModel usuario = usuarioInterface.registroUsuario(login, nome, senha, sqlDate, cpf, nivel);

        String token = generateJWTToken(usuario).toString();

        //return login + "\n" + nome + "\n" + senha + "\n" + dataNasc + "\n"  ;

        Map<String, String> map = new HashMap<>();
        map.put("codeHttp", HttpStatus.OK.toString());
        map.put("message", "Usuario registrado com sucesso!");
        map.put("Status", "Success!");
        map.put("id", Integer.toString(usuario.getId()));
        map.put("token", token);

//        System.out.println(usuario.getId());

        return new ResponseEntity<>(map, HttpStatus.OK);

    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> loginUsuario(@RequestBody Map<String, Object> usuarioMap) throws ParseException {

        String login = (String) usuarioMap.get("login");
        String senha = (String) usuarioMap.get("senha");

        UsuarioModel usuario = usuarioInterface.validadorUsuario(login, senha);

        String token = generateJWTToken(usuario).toString();

//        System.out.println(usuario.getNivel());

        String nivel = usuario.getNivel();

//        if(usuario.getNivel().equalsIgnoreCase("2")){
//            nivel = usuario.getNivel();
//        }



        Map<String, Object> map = new LinkedHashMap<>();
        map.put("codeHttp", HttpStatus.OK.toString());
        map.put("message", "Usuario Logado!");
        map.put("Status", "Success!");
        map.put("user_level", nivel );
        map.put("token",token);
        map.put("dadosUsuario",usuario);


        return new ResponseEntity<>(map, HttpStatus.OK);

    }


    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logoutUsuario(@RequestHeader("Authorization") String tokenHeader) {
        if (tokenHeader != null && tokenHeader.startsWith("Token ")) {
            String token = tokenHeader.substring(6);

            // Revoga o token chamando o método do filtro
            AuthFilter.revokeToken(token);

            Map<String, String> response = new HashMap<>();
            response.put("codeHttp", HttpStatus.OK.toString());
            response.put("message", "Logout realizado com sucesso!");
            response.put("Status", "Success");

            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "codeHttp", HttpStatus.BAD_REQUEST.toString(),
                    "message", "Token inválido ou ausente",
                    "Status", "Error"
            ));
        }
    }


    @GetMapping("/buscarTodosUsuarios")
    public ResponseEntity<Map<String, Object>> buscarTodosUsuarios(
                                                        @RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.replace("Token ", "");

        Map<String, Object> responseMap = new LinkedHashMap<>();

        String nivel;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(constants.API_SECRET_KEY.getBytes())  // Utiliza a chave secreta para assinar o token
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            nivel = (String) ((io.jsonwebtoken.Claims) claims).get("nivel");
        } catch (Exception e) {

            responseMap.put("codeHttp", HttpStatus.UNAUTHORIZED.toString());
            responseMap.put("message", "Token inválido ou expirado.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.UNAUTHORIZED);
        }

        // Adicionar validação de nível, se necessário (ex: apenas admins podem buscar todos os usuários)
        if (nivel == null || !nivel.equals("2")) {  // Supondo que nível "2" seja administrador
            responseMap.put("codeHttp", HttpStatus.FORBIDDEN.toString());
            responseMap.put("message", "Acesso negado. Apenas administradores podem acessar este recurso.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.FORBIDDEN);
        }

        // Resgatar todos os usuários
        List<UsuarioModel> usuarios = usuarioInterface.buscarTodosUsuarios();

        // Montar a resposta de sucesso
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("codeHttp", HttpStatus.OK.toString());
        response.put("message", "Usuários resgatados com sucesso!");
        response.put("Status", "Success");
        response.put("Usuários", usuarios);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    @GetMapping("/buscarUsuario")
    public ResponseEntity<Map<String, Object>> buscarUsuario(
            @RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.replace("Token ", "");

        Map<String, Object> responseMap = new LinkedHashMap<>();

//        String nivel;
        Integer id;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(constants.API_SECRET_KEY.getBytes())  // Utiliza a chave secreta para assinar o token
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

//            nivel = (String) ((io.jsonwebtoken.Claims) claims).get("nivel");
            id = (Integer) ((io.jsonwebtoken.Claims) claims).get("id");
        } catch (Exception e) {

            responseMap.put("codeHttp", HttpStatus.UNAUTHORIZED.toString());
            responseMap.put("message", "Token inválido ou expirado.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.UNAUTHORIZED);
        }

//        // Adicionar validação de nível, se necessário (ex: apenas admins podem buscar todos os usuários)
//        if (nivel == null || !nivel.equals("2")) {  // Supondo que nível "2" seja administrador
//            responseMap.put("codeHttp", HttpStatus.FORBIDDEN.toString());
//            responseMap.put("message", "Acesso negado. Apenas administradores podem acessar este recurso.");
//            responseMap.put("Status", "Error");
//            return new ResponseEntity<>(responseMap, HttpStatus.FORBIDDEN);
//        }

        // Resgatar todos os usuários
        UsuarioModel usuario = usuarioInterface.buscarUsuario(id);

        // Montar a resposta de sucesso
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("codeHttp", HttpStatus.OK.toString());
        response.put("message", "Usuário resgatado com sucesso!");
        response.put("Status", "Success");
        response.put("Usuário", usuario);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    @PutMapping("/atualizar")
    public ResponseEntity<Map<String, String>> atualizarUsuario(
            @RequestBody Map<String, Object> usuarioMap,
            @RequestHeader("Authorization") String authorizationHeader) {

        Map<String, String> responseMap = new HashMap<>();


        // Verifica se o ID do usuário foi fornecido no corpo da solicitação
//        if (!usuarioMap.containsKey("senhaAtual")) {
//            responseMap.put("codeHttp", HttpStatus.BAD_REQUEST.toString());
//            responseMap.put("message", "ID do usuário ou senha atual não fornecido.");
//            responseMap.put("Status", "Error");
//            return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
//        }

//        Integer id = (Integer) usuarioMap.get("id");
//        String senhaAtual = (String) usuarioMap.get("senhaAtual");
        String token = authorizationHeader.replace("Token ", "");

        Integer id;
        String nivel;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(constants.API_SECRET_KEY.getBytes())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            id = (Integer)  claims.get("id");
            nivel = (String) ((io.jsonwebtoken.Claims) claims).get("nivel");
        } catch (Exception e) {
            responseMap.put("codeHttp", HttpStatus.UNAUTHORIZED.toString());
            responseMap.put("message", "Token inválido ou expirado.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.UNAUTHORIZED);
        }

        // Busca o usuário atual no banco de dados
        UsuarioModel usuarioAtual = usuarioRepository.findByID(id);
        if (usuarioAtual == null) {
            responseMap.put("codeHttp", HttpStatus.NOT_FOUND.toString());
            responseMap.put("message", "Usuário não encontrado.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
        }



        // Verifica se a senha atual corresponde
//        if (!passwordEncoder.matches(senhaAtual, usuarioAtual.getSenha())) {
//            responseMap.put("codeHttp", HttpStatus.UNAUTHORIZED.toString());
//            responseMap.put("message", "Senha atual incorreta.");
//            responseMap.put("Status", "Error");
//            return new ResponseEntity<>(responseMap, HttpStatus.UNAUTHORIZED);
//        }

        // Extrai dados do corpo da solicitação para atualizar apenas os fornecidos
        String login = (String) usuarioMap.get("login");
        String nome = (String) usuarioMap.get("nome");
//        String novaSenha = (String) usuarioMap.get("senhaNova");
        String dataNascimentoStr = (String) usuarioMap.get("dataNascimento");
        String cpf = (String) usuarioMap.get("cpf");

        LocalDate dataNascimento = null;
        if (dataNascimentoStr != null) {
            try {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");
                dataNascimento = LocalDate.parse(dataNascimentoStr, formatter);
            } catch (Exception e) {
                responseMap.put("codeHttp", HttpStatus.BAD_REQUEST.toString());
                responseMap.put("message", "Data de nascimento inválida.");
                responseMap.put("Status", "Error");
                return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
            }
        }

        cpf = (cpf != null) ? cpf : usuarioAtual.getCpf();

        try {
            // Atualiza o usuário com os novos dados
            UsuarioModel usuarioAtualizado = usuarioInterface.atualizarUsuario(
                    login != null ? login : usuarioAtual.getLogin(),
                    nome != null ? nome : usuarioAtual.getNome(),
                    dataNascimento != null ? java.sql.Date.valueOf(dataNascimento) : null,
                    cpf,
                    nivel,
                    id
            );

            System.out.println(usuarioAtualizado);

            responseMap.put("codeHttp", HttpStatus.OK.toString());
            responseMap.put("message", "Usuário atualizado com sucesso!");
            responseMap.put("Status", "Success");
            return new ResponseEntity<>(responseMap, HttpStatus.OK);

        } catch (EtAuthException e) {
            responseMap.put("codeHttp", HttpStatus.UNAUTHORIZED.toString());
            responseMap.put("message", e.getMessage());
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            responseMap.put("codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString());
            responseMap.put("message", "Erro ao atualizar o usuário: " + e.getMessage());
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



    @DeleteMapping("/deletar")
    public ResponseEntity<Map<String, String>> deletarUsuario(@RequestBody Map<String, Object> usuarioMap,
                                                              @RequestHeader("Authorization") String authorizationHeader) {
        Map<String, String> responseMap = new HashMap<>();

        // Verificar se o ID do usuário foi fornecido
        if (!usuarioMap.containsKey("id")) {
            responseMap.put("codeHttp", HttpStatus.BAD_REQUEST.toString());
            responseMap.put("message", "ID do usuário não fornecido.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
        }

        Integer id = (Integer) usuarioMap.get("id");

        // Extrair o token do cabeçalho Authorization (ex: "Bearer <token>")
        String token = authorizationHeader.replace("Token ", "");

        // Decodificar o token JWT e extrair o campo "nivel"
        String nivel;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(constants.API_SECRET_KEY.getBytes())  // Utiliza a chave secreta para assinar o token
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            nivel = (String) ((io.jsonwebtoken.Claims) claims).get("nivel");
        } catch (Exception e) {
            responseMap.put("codeHttp", HttpStatus.UNAUTHORIZED.toString());
            responseMap.put("message", "Token inválido ou expirado.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.UNAUTHORIZED);
        }

        // Verificar o nível de permissão
        if (nivel == null || !nivel.equals("2")) {
            responseMap.put("codeHttp", HttpStatus.FORBIDDEN.toString());
            responseMap.put("message", "Acesso negado. Apenas administradores podem acessar este recurso.");
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.FORBIDDEN);
        }

        // Tentar deletar o usuário
        try {
            UsuarioModel usuarioDeletado = usuarioInterface.deletarUsuario(id);  // Suponha que o método retorne o usuário deletado

            if (usuarioDeletado == null) {
                responseMap.put("codeHttp", HttpStatus.NOT_FOUND.toString());
                responseMap.put("message", "Usuário não encontrado.");
                responseMap.put("Status", "Error");
                return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
            }

            responseMap.put("codeHttp", HttpStatus.OK.toString());
            responseMap.put("message", "Usuário deletado com sucesso!");
            responseMap.put("Status", "Success");
            return new ResponseEntity<>(responseMap, HttpStatus.OK);

        } catch (Exception e) {
            // Capturar qualquer erro durante o processo de exclusão
            responseMap.put("codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString());
            responseMap.put("message", "Erro ao deletar o usuário: " + e.getMessage());
            responseMap.put("Status", "Error");
            return new ResponseEntity<>(responseMap, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    private String generateJWTToken(UsuarioModel usuario) {
        long timestamp = System.currentTimeMillis();

        // Gerar uma chave secreta com base na sua chave existente
        SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());

        // Verifica se o usuário é administrador (nível 2)
        if (usuario.getNivel().equals("2")) {
            // Gera um token especial para administradores, com claims ou validade diferente
            return Jwts.builder()
                    .setIssuedAt(new Date(timestamp))
                    .setExpiration(new Date(timestamp + constants.TOKEN_VALIDITY)) // Exemplo: validade mais longa para admins
                    .claim("id", usuario.getId())
                    .claim("login", usuario.getLogin())
                    .claim("nome", usuario.getNome())
                    .claim("cpf", usuario.getCpf())
                    .claim("dataNascimento", usuario.getDataNascimento())
                    .claim("nivel", "2")
                    .signWith(secretKey, SignatureAlgorithm.HS256)
                    .compact();
        } else {
            // Gera um token padrão para usuários comuns
            return Jwts.builder()
                    .setIssuedAt(new Date(timestamp))
                    .setExpiration(new Date(timestamp + constants.TOKEN_VALIDITY))
                    .claim("id", usuario.getId())
                    .claim("login", usuario.getLogin())
                    .claim("nome", usuario.getNome())
                    .claim("cpf", usuario.getCpf())
                    .claim("dataNascimento", usuario.getDataNascimento())
                    .signWith(secretKey, SignatureAlgorithm.HS256)
                    .compact();
        }
    }



}
