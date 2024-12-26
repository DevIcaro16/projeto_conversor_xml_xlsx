package com.ILG.conversor_xml_api.Repositories;

import com.ILG.conversor_xml_api.Exceptions.EtAuthException;
import com.ILG.conversor_xml_api.Models.UsuarioModel;

import java.util.List;

public interface UsuarioRepository {
    Integer create(String login, String nome, String senha, java.sql.Date dataNascimento, String cpf, String nivel) throws EtAuthException;

    Integer update(String login, String nome, java.sql.Date dataNascimento, String cpf, String nivel, Integer id) throws EtAuthException;

    UsuarioModel findByLoginAndPassword(String login, String senha) throws EtAuthException;

    Integer getCountByLogin(String login) throws EtAuthException;

    Integer getCountByCPF(String cpf) throws EtAuthException;

    UsuarioModel findByID(Integer id) throws EtAuthException;

    List<UsuarioModel> findAll() throws EtAuthException;

    void deleteByID(Integer id) throws EtAuthException;
}
