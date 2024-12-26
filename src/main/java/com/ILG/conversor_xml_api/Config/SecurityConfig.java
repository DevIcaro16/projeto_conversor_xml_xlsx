package com.ILG.conversor_xml_api.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .addFilterBefore(new AuthFilter())
//                .addFilterBefore(new ConnectionAuthFilter(), AuthFilter.class) // Adiciona o ConnectionAuthFilter
//                .authorizeRequests()
//                .anyRequest().authenticated();
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

