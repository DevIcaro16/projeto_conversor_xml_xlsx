package com.ILG.conversor_xml_api.Interfaces;

import com.ILG.conversor_xml_api.Exceptions.EtAuthException;
import com.ILG.conversor_xml_api.Models.UsuarioModel;

import java.util.List;

public interface UsuarioInterface {

    UsuarioModel validadorUsuario(String login, String senha) throws EtAuthException;

    UsuarioModel registroUsuario(String login, String nome, String senha, java.sql.Date dataNascimento, String cpf, String nivel) throws EtAuthException;

    UsuarioModel atualizarUsuario(String login, String nome, java.sql.Date dataNascimento, String cpf, String nivel, Integer id) throws EtAuthException;

    UsuarioModel deletarUsuario(Integer id) throws EtAuthException;

    List<UsuarioModel> buscarTodosUsuarios() throws EtAuthException;

    UsuarioModel buscarUsuario(Integer id) throws EtAuthException;
}
