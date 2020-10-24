package br.com.gobsio.multisession.services.security;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import br.com.gobsio.multisession.config.cookies.SSIDCookieWrapper;
import br.com.gobsio.multisession.config.cookies.SignedUserInfoCookie;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionDetails;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionPrincipal;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionPrincipalsRepository;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionRepository;

@Service
public class SecurityService {

    @Autowired
    private TokenStore jwtTokenStore;

    @Autowired
    private SSIDCookieWrapper ssidCookieWrapper;

    @Autowired
    private HttpSessionRepository httpSessionDetailsRepository;

    @Autowired
    private HttpSessionPrincipalsRepository httpSessionPrincipalsRepository;

    // @formatter:off    
    public String getSSIDFromRequest(HttpServletRequest request) {
        return ssidCookieWrapper.getSSIDFromRequest(request);
    }

    public boolean logoutOAuthUser(String oauthuser, HttpServletRequest request) {
        UUID hsid = UUID.fromString(getSSIDFromRequest(request));

        HttpSessionDetails session = this.httpSessionDetailsRepository.findById(hsid).orElse(null);
        List<HttpSessionPrincipal> principals = this.httpSessionPrincipalsRepository.findBySessionId(hsid);

        // descobrir qual principal estamos removendo...
        HttpSessionPrincipal principal = principals.stream()
                                            .filter(p -> p.getAlias().equals(oauthuser))
                                            .findFirst().orElse(null);
        
        
        if (principals.size() > 1) { 

            // removing the specified principal.
            this.httpSessionPrincipalsRepository.delete(principal);
            
            // find another principal to replace the removed one.
            HttpSessionPrincipal switchPrincipal = principals.stream()
                                            .filter(p -> !p.getAlias().equals(oauthuser))
                                            .findFirst().orElse(null);

            // @method pass a principal
            session.setAlias(switchPrincipal.getAlias());
            session.setPrincipal(switchPrincipal.getPrincipal());

            this.httpSessionDetailsRepository.save(session);
            // @method pass a principal

            this.updateSecurityContext(session);

            return false;
        } else {
            // removing the specified principal.
            this.httpSessionPrincipalsRepository.delete(principal);
            
            // removing the session.
            this.httpSessionDetailsRepository.delete(session);

            this.emptySecurityContext();

            return true;
        }

    }

    public void switchOAuthUser(String oauthuser, HttpServletRequest request) {
        UUID hsid = UUID.fromString(getSSIDFromRequest(request));

        HttpSessionDetails session = this.httpSessionDetailsRepository.findById(hsid).orElse(null);
        HttpSessionPrincipal principal = this.httpSessionPrincipalsRepository.findBySessionIdAndAlias(hsid, oauthuser);

        session.setAlias(principal.getAlias());
        session.setPrincipal(principal.getPrincipal());

        this.httpSessionDetailsRepository.save(session);

        this.updateSecurityContext(session);
    }


    public Optional<OAuth2Authentication> readCookieAuthenticationFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return Optional.empty();
        }

        Cookie cookie = Stream.of(cookies)
                .filter(c -> SignedUserInfoCookie.NAME.equals(c.getName()))
                .findFirst().orElse(null);

        if (cookie == null) {
            return Optional.empty();
        }

        return Optional.of(null);
    }

    public Optional<OAuth2Authentication> readJwtAuthenticationFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null) {
            return Optional.empty();
        }

        String jwtTokenValue = authorizationHeader.replace("Bearer", "").trim();

        return Optional.of(jwtTokenStore.readAuthentication(jwtTokenValue));
    }

    public void getAuthUsersSessionId(UUID ssid) {
    }


    private void emptySecurityContext() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(context);
    }

    private void updateSecurityContext(HttpSessionDetails session) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            session.getPrincipal(), "", Arrays.asList()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void updateSecurityContext(Authentication authentication) {
    }

}