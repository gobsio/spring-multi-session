package br.com.gobsio.multisession.services.userdetails;

// import br.com.ottimizza.application.model.Authority;
// import br.com.ottimizza.application.model.user.User;
// import br.com.ottimizza.application.repositories.users.UsersRepository;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.gobsio.multisession.domain.authority.Authority;
import br.com.gobsio.multisession.domain.users.User;
import br.com.gobsio.multisession.repositories.users.UserRepository;

@Service("userDetailsService")
@Transactional
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    @Autowired
    UserRepository usersRepository;

    @Autowired
    public void setUserRepository(UserRepository usersRepository) {
        this.usersRepository = usersRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // User user = usersRepository.findByUsername(username).orElse(null);

        // org.springframework.security.core.userdetails.User userDetails = new org.springframework.security.core.userdetails.User(
        //         user.getUsername(), user.getPassword(), user.getEnabled(), true, true, true,
        //         getGrantedAuthorities(user));

        return usersRepository.findByUsername(username)
                .map(user -> new org.springframework.security.core.userdetails.User(user.getUsername(),
                        user.getPassword(), user.getEnabled(), true, true, true, getGrantedAuthorities(user)))
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " Not found"));

    }

    private Collection<GrantedAuthority> getGrantedAuthorities(User user) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        // for (Authority authority : user.getAuthorities()) {
        // for (String authority :
        // usersRepository.fetchAuthoritiesByUsername(user.getUsername())) {
        // GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authority);
        // grantedAuthorities.add(grantedAuthority);
        // }

        return grantedAuthorities;
    }
}
