package com.ILG.conversor_xml_api.Repositories;

import com.ILG.conversor_xml_api.Exceptions.EtAuthException;
import com.ILG.conversor_xml_api.Models.UsuarioModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;

@Repository
public class UsuarioRepositoryImpl implements UsuarioRepository{

    private static final String SqlCreate = "INSERT INTO usuarios (login, nome, senha, dataNascimento, cpf, nivel) VALUES (?, ?, ?, ?, ?, ?)";

    private static final String SqlUpdate = "UPDATE usuarios SET login = ?, nome = ?, dataNascimento = ?, cpf = ?, nivel = ? WHERE id = ?";

    private static final String SqlCountByLogin = "SELECT COUNT(*) FROM usuarios WHERE login = ?";

    private static final  String SqlCountByCPF = "SELECT COUNT(*) FROM usuarios WHERE cpf = ?";

    private static final String SqlfindByID = "SELECT * FROM usuarios WHERE id = ?";

    private static final String SqlfindAll = "SELECT * FROM usuarios ORDER BY ID";

    private static final String SqlDeleteByID = "DELETE FROM usuarios WHERE id = ?";

    private static final String SqlfindByLoginAndPassword = "SELECT * FROM usuarios WHERE login = ?";


    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Integer create(String login, String nome, String senha, java.sql.Date dataNascimento, String cpf, String nivel) throws EtAuthException {

        String senhaCrypto = passwordEncoder.encode(senha);

        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(connection -> {
                PreparedStatement preparedStatement = connection.prepareStatement(SqlCreate, Statement.RETURN_GENERATED_KEYS);
                preparedStatement.setString(1, login);
                preparedStatement.setString(2, nome);
                preparedStatement.setString(3, senhaCrypto);
                preparedStatement.setDate(4, dataNascimento);
                preparedStatement.setString(5, cpf);
                preparedStatement.setString(6, nivel);

                return preparedStatement;

            }, keyHolder);

            return (Integer) keyHolder.getKeys().get("id"); // Aqui, o id gerado será retornado

        } catch (Exception e) {
            throw new EtAuthException("Não foi possível criar seu registro!.\n");
        }
    }

//    @Override
    public Integer update(String login, String nome, java.sql.Date dataNascimento, String cpf, String nivel, Integer id) throws EtAuthException{

//        String senhaCrypto = passwordEncoder.encode(senha);

        try{
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(connection -> {
                PreparedStatement preparedStatement = connection.prepareStatement(SqlUpdate, Statement.RETURN_GENERATED_KEYS);
                preparedStatement.setString(1, login);
                preparedStatement.setString(2, nome);
                preparedStatement.setDate(3, dataNascimento);
                preparedStatement.setString(4, cpf);
                preparedStatement.setString(5, nivel);
                preparedStatement.setInt(6, id);

                return preparedStatement;

            }, keyHolder);

            return (Integer) keyHolder.getKeys().get("id");

        }catch(Exception e){
            throw  new EtAuthException("Erro ao Atualizar o Usuário!" + e.getMessage());
        }
    }

    @Override
    public UsuarioModel findByLoginAndPassword(String login, String senha) throws EtAuthException {
        try {
            // Buscar o objeto Usuario no banco de dados usando o login
            UsuarioModel usuario = jdbcTemplate.queryForObject(SqlfindByLoginAndPassword, new Object[]{login}, usuarioRowMapper);

            // Verificar se o usuário existe
            if (usuario == null) {
                throw new EtAuthException("Credenciais Inválidas! Usuário não encontrado!");
            }

            // Verificar se a senha fornecida corresponde à senha criptografada
             if (!passwordEncoder.matches(senha, usuario.getSenha())) {
                throw new EtAuthException("Credenciais Inválidas!");
            }

            // Retornar o ID do usuário se as credenciais forem válidas
            return usuario;

        } catch (EmptyResultDataAccessException e) {
            throw new EtAuthException("Credenciais Inválidas! Usuário não encontrado!");
        } catch (Exception e) {
            throw new EtAuthException("Erro ao buscar usuário: " + e.getMessage());
        }
    }


    @Override
    public Integer getCountByLogin(String login) {
        return jdbcTemplate.queryForObject(SqlCountByLogin, new Object[]{login}, Integer.class);
    }

    @Override
    public Integer getCountByCPF(String cpf) {
        return jdbcTemplate.queryForObject(SqlCountByCPF, new Object[]{cpf}, Integer.class);
    }

    @Override
    public UsuarioModel findByID(Integer id) {
        try {
            return jdbcTemplate.queryForObject(SqlfindByID, new Object[]{id}, usuarioRowMapper);
        } catch (EmptyResultDataAccessException e) {
            return null; // Retorna null se o usuário não for encontrado
        }
    }

    @Override
    public List<UsuarioModel> findAll() {
        try {
            return jdbcTemplate.query(SqlfindAll, usuarioRowMapper);
        } catch (EmptyResultDataAccessException e) {
            return List.of(); // Retorna uma lista vazia em vez de null
        }
    }


    @Override
    public void deleteByID(Integer id) {
        jdbcTemplate.update(SqlDeleteByID, id);  // Usa update ao invés de queryForObject
    }

    private RowMapper<UsuarioModel> usuarioRowMapper = (rs, rowNum) -> {
        return new UsuarioModel(
                rs.getInt("id"),
                rs.getString("login"),
                rs.getString("nome"),
                rs.getString("senha"),
                rs.getDate("dataNascimento"),
                rs.getString("cpf"),
                rs.getString("nivel")
        );
    };
}
