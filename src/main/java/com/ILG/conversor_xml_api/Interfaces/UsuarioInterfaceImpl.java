package com.ILG.conversor_xml_api.Interfaces;

import com.ILG.conversor_xml_api.Exceptions.EtAuthException;
import com.ILG.conversor_xml_api.Models.UsuarioModel;
import com.ILG.conversor_xml_api.Repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Date;
import java.util.List;
import java.util.regex.Pattern;

@Service
@Transactional
public class UsuarioInterfaceImpl implements UsuarioInterface {

    @Autowired
    UsuarioRepository usuarioRepository;

    @Override
    public UsuarioModel validadorUsuario(String login, String senha) throws EtAuthException {

        if(login != null && senha != null){

            login = login.trim().toLowerCase();
            senha = senha.trim();

            return usuarioRepository.findByLoginAndPassword(login, senha);

        }

        return null;
    }

    @Override
    public UsuarioModel registroUsuario(String login, String nome, String senha, java.sql.Date dataNascimento, String cpf, String nivel) throws EtAuthException {
        Pattern pattern = Pattern.compile("^(.+)@(.+)$");

        if(login != null){
            login = login.trim().toLowerCase();
        }

        if(!pattern.matcher(login).matches()){
            throw new EtAuthException("Email Inválido!");
        }

        Integer countLogin = usuarioRepository.getCountByLogin(login);

        if(countLogin > 0){
            throw new EtAuthException("Email Já Cadastrado!");
        }

        Integer countCPF = usuarioRepository.getCountByCPF(cpf);

        if(countCPF > 0){
            throw new EtAuthException("CPF Já Cadastrado!");
        }

        Integer usuarioID = usuarioRepository.create(login, nome, senha, dataNascimento, cpf, nivel );

        return usuarioRepository.findByID(usuarioID);
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UsuarioModel atualizarUsuario(String login, String nome, java.sql.Date dataNascimento, String cpf, String nivel, Integer id) throws EtAuthException {

//        UsuarioModel usuario = usuarioRepository.findByLoginAndPassword(login, senhaAtual);
        UsuarioModel usuario = usuarioRepository.findByID(id);

        if (usuario == null) {
            throw new EtAuthException("Usuário Não Encontrado!.");
        }

//        String senhaCrypto = novaSenha != null ? passwordEncoder.encode(novaSenha) : usuario.getSenha();

        usuarioRepository.update(login, nome, dataNascimento, cpf, nivel, id);


        return usuarioRepository.findByID(usuario.getId());
    }


    @Override
    public UsuarioModel deletarUsuario(Integer id) throws EtAuthException {
        UsuarioModel usuario = usuarioRepository.findByID(id);
        System.out.println(usuario);
        if (usuario != null) {
            usuarioRepository.deleteByID(id);
        }else{
            throw new EtAuthException("Usuário não encontrado!");
        }

        return usuario;
    }

    public UsuarioModel buscarUsuario(Integer id) throws EtAuthException {

        UsuarioModel usuario =  usuarioRepository.findByID(id);

        System.out.println(usuario);
        if (usuario == null) {
            throw new EtAuthException("Usuário não Encontrado!");
        }

        return usuario;


    }public List<UsuarioModel> buscarTodosUsuarios() throws EtAuthException {

        List<UsuarioModel> usuarios = (List<UsuarioModel>) usuarioRepository.findAll();

        System.out.println(usuarios);
        if (usuarios == null) {
            throw new EtAuthException("Usuários não Encontrados!");
        }

        return usuarios;
    }

}
