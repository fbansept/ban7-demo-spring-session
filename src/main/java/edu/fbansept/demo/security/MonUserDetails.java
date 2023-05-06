package edu.fbansept.demo.security;

import edu.fbansept.demo.model.Utilisateur;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class MonUserDetails implements UserDetails {

    private String email;
    private String motDePasse;
    private boolean isAdmin;

    public MonUserDetails(String email, String motDePasse, boolean isAdmin) {
        this.email = email;
        this.motDePasse = motDePasse;
        this.isAdmin = isAdmin;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return List.of(new SimpleGrantedAuthority(isAdmin ? "ROLE_ADMINISTRATEUR" : "ROLE_UTILISATEUR"));

    }

    @Override
    public String getPassword() {
        return motDePasse;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
