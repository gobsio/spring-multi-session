package br.com.gobsio.multisession.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;

public class UserInfo extends User {

    private static final String EMPTY_PASSWORD = "";

    private final String username;
    private final String password;
    private final Set<GrantedAuthority> authorities;

    private String colour;

    public UserInfo(String username, Set<GrantedAuthority> authorities) {
        this(username, "", authorities);
    }

    public UserInfo(String username, Set<GrantedAuthority> authorities, String colour) {
        this(username, "", authorities);
        this.colour = colour;
    }

    public UserInfo(String username, String password, Set<GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return EMPTY_PASSWORD;
    }

    @Override
    public String getUsername() {
        return username;
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

    public Optional<String> getColour() {
        return Optional.ofNullable(colour);
    }

    public void setColour(String colour) {
        if (colour == null || colour.isBlank())
            this.colour = null;
        else
            this.colour = colour;
    }
}