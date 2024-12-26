package com.ILG.conversor_xml_api.Models;

import java.util.Date;

public class UsuarioModel {

    private Integer id;
    private String login;
    private String nome;
    private String senha;
    private Date dataNascimento;
    private String cpf;
    private String nivel;



    public Integer getId() {
        return id;
    }

    public void setID(Integer id) {
        this.id = id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    public Date getDataNascimento() {
        return dataNascimento;
    }

    public void setDataNascimento(Date dataNascimento) {
        this.dataNascimento = dataNascimento;
    }

    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public String getNivel() {
        return nivel;
    }

    public void setNivel(String nivel) {
        this.nivel = nivel;
    }

    public UsuarioModel(
                        Integer id, String login, String nome, String senha, java.sql.Date dataNascimento,
                        String cpf, String nivel) {
        this.id = id;
        this.login = login;
        this.nome = nome;
        this.senha = senha;
        this.dataNascimento = new Date();
        this.cpf = cpf;
        this.nivel = nivel;

    }


}
