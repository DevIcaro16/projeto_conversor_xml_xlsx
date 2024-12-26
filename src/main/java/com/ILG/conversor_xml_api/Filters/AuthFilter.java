package com.ILG.conversor_xml_api.Filters;

import com.ILG.conversor_xml_api.Config.constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class AuthFilter extends GenericFilterBean {

    // Armazena os tokens revogados temporariamente em memória
    private static final Set<String> revokedTokens = new HashSet<>();

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Token ")) {
            String token = authHeader.substring(6);

            // Verifica se o token foi revogado
            if (revokedTokens.contains(token)) {
                response.sendError(HttpStatus.UNAUTHORIZED.value(), "Acesso Encerrado! Por favor, faça login novamente.");
                return;
            }

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(constants.API_SECRET_KEY.getBytes())
                        .parseClaimsJws(token)
                        .getBody();

                if (claims != null && claims.get("id") != null) {
                    request.setAttribute("id", Integer.parseInt(claims.get("id").toString()));

                    String nivel = claims.get("nivel", String.class);
                    request.setAttribute("nivel", nivel);

                    // Protege endpoint específico para admins
                    String requestURI = request.getRequestURI();
                    if (requestURI.equals("/api/usuarios/deletar") && (nivel == null || !nivel.equals("2"))) {
                        response.sendError(HttpStatus.FORBIDDEN.value(), "Acesso negado. Apenas administradores podem acessar este recurso.");
                        return;
                    }
                } else {
                    response.sendError(HttpStatus.FORBIDDEN.value(), "Token não contém ID do usuário!");
                    return;
                }

            } catch (Exception e) {
                response.sendError(HttpStatus.FORBIDDEN.value(), "Token expirado ou inválido.");
                return;
            }
        } else {
            response.sendError(HttpStatus.FORBIDDEN.value(), "Token de autorização deve ser providenciado para acessar este conteúdo!");
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    // Método para adicionar um token à lista de tokens revogados
    public static void revokeToken(String token) {
        revokedTokens.add(token);
    }
}
