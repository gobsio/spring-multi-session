package br.com.gobsio.multisession.config.cookies;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import br.com.gobsio.multisession.domain.UserInfo;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionDetails;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionPrincipal;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionPrincipalId;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionPrincipalsRepository;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionRepository;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.implementation.bytecode.constant.NullConstant;

@Slf4j
@Component
public class CookieSecurityContextRepository implements SecurityContextRepository {

    private static final String EMPTY_CREDENTIALS = "";

    private static final String ANONYMOUS_USER = "anonymousUser";

    private final String cookieHmacKey;

    @Autowired
    private TokenStore jwtTokenStore;

    @Autowired
    private HttpSessionRepository sessionRepository;

    @Autowired
    private HttpSessionPrincipalsRepository httpSessionPrincipalsRepository;

    @Autowired
    private SSIDCookieWrapper ssidCookieWrapper;

    public CookieSecurityContextRepository(@Value("${auth.cookie.hmac-key}") String cookieHmacKey) {
        this.cookieHmacKey = cookieHmacKey;
    }

    @Override // @formatter:off
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        HttpServletResponse response = requestResponseHolder.getResponse();
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        requestResponseHolder.setResponse(new SaveToCookieResponseWrapper(request, response));

        // checking first for a Authorization Header...
        OAuth2Authentication jwtAuthentication = readAuthenticationFromAccessToken(request).orElse(null);

        if (jwtAuthentication != null) {
            context.setAuthentication(jwtAuthentication);
        } else {
            User userinfo = ssidCookieWrapper.getUserDetailsFromRequest(request);

            if (userinfo != null) {
                UsernamePasswordAuthenticationToken cookieAuthentication = new UsernamePasswordAuthenticationToken(
                    userinfo, EMPTY_CREDENTIALS, userinfo.getAuthorities()
                );
                context.setAuthentication(cookieAuthentication);
            }
        }

        return context;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        // SaveToCookieResponseWrapper responseWrapper = (SaveToCookieResponseWrapper) response;
        // if (!responseWrapper.isContextSaved()) {
        //     responseWrapper.saveContext(context);
        // }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return readCookieFromRequest(request).isPresent();
    }

    /**
     * Cookie
     * 
     * 
     */
    private Optional<User> readUserInfoFromCookie(HttpServletRequest request) {
        return readCookieFromRequest(request).map(ssidCookieWrapper::getUserDetailsFromCookie);
    }

    private Optional<Cookie> readCookieFromRequest(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }

        Optional<Cookie> maybeCookie = Stream.of(request.getCookies())
                .filter(c -> SignedUserInfoCookie.NAME.equals(c.getName())).findFirst();

        return maybeCookie;
    }

    /**
     * Quando existe um cookie, verifica a validade e devolve userinfo.
     */
    private User createUserInfo(Cookie cookie) {
        return ssidCookieWrapper.getUserDetailsFromCookie(cookie);
    }

    private Optional<OAuth2Authentication> readAuthenticationFromAccessToken(HttpServletRequest request) {
        return readJwtFromRequest(request);
    }

    private Optional<OAuth2Authentication> readJwtFromRequest(HttpServletRequest request) {
        if (request.getHeader("Authorization") == null) {
            return Optional.empty();
        }

        String jwtTokenValue = request.getHeader("Authorization").replace("Bearer", "").trim();

        OAuth2Authentication authetication = this.jwtTokenStore.readAuthentication(jwtTokenValue);

        return Optional.of(authetication);
    }

    // @Slf4j
    private class SaveToCookieResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {
        private final HttpServletRequest request;

        SaveToCookieResponseWrapper(HttpServletRequest request, HttpServletResponse response) {
            super(response, true);
            this.request = request;
        }

        @Override
        protected void saveContext(SecurityContext securityContext) {
            HttpServletResponse response = (HttpServletResponse) getResponse();
            Authentication authentication = securityContext.getAuthentication();

            if (authentication == null) {
                // LOG.debug("No securityContext.authentication, skip saveContext");
                return;
            }

            if (ANONYMOUS_USER.equals(authentication.getPrincipal())) {
                // LOG.debug("Anonymous User SecurityContext, skip saveContext");
                return;
            }

            if (!(authentication.getPrincipal() instanceof User)) {
                // LOG.warn("securityContext.authentication.principal of unexpected type {},
                // skip saveContext",
                // authentication.getPrincipal().getClass().getCanonicalName());
                return;
            }

            User userInfo = (User) authentication.getPrincipal();

            // we first try to get an existing ssid cookie.
            SignedUserInfoCookie cookie1 = ssidCookieWrapper.getUserInfoCookie(request);

            log.info("    ");
            log.info("  - " + cookie1);
            log.info("    ");

            UUID ssid = cookie1 == null ? UUID.randomUUID() : UUID.fromString(cookie1.getSSID());

            if (cookie1 == null) {
                String principalName = userInfo.getUsername();
                String principalAlias = "0";

                HttpSessionPrincipal principal = HttpSessionPrincipal.builder()
                        .id(HttpSessionPrincipalId.builder().id(ssid).principal(principalName).build()).sessionId(ssid)
                        .alias(principalAlias).principal(principalName).build();

                HttpSessionDetails sessionDetails = HttpSessionDetails.builder().id(ssid).alias(principalAlias)
                        .principal(principalName).build();

                sessionRepository.save(sessionDetails);
                httpSessionPrincipalsRepository.save(principal);

                // String ssid = cookie.getSSID() ? cookie.getSSID() : "";
                // User userInfo = (User) authentication.getPrincipal();
                SignedUserInfoCookie cookie = new SignedUserInfoCookie(sessionDetails.getId().toString(), userInfo,
                        cookieHmacKey);
                cookie.setSecure(request.isSecure());

                //
                setupSessionAttributes(cookie);

                response.addCookie(cookie);
            } else {
                // busca sessao por id
                HttpSessionDetails session = sessionRepository.findById(ssid).orElse(null);

                if (session != null) {
                    // List all the principals
                    String principalAlias = "";
                    String principalName = "";

                    List<HttpSessionPrincipal> authenticated = httpSessionPrincipalsRepository.findBySessionId(ssid);

                    List<HttpSessionPrincipal> principalsFiltered = authenticated.stream()
                            .filter(p -> p.getPrincipal().equals(userInfo.getUsername())).collect(Collectors.toList());

                    if (principalsFiltered.size() == 0) {
                        principalAlias = String.valueOf(authenticated.size());
                        principalName = userInfo.getUsername();
                    } else {
                        principalAlias = principalsFiltered.get(0).getAlias();
                        principalName = principalsFiltered.get(0).getPrincipal();
                    }

                    HttpSessionPrincipal principal = new HttpSessionPrincipal();

                    HttpSessionPrincipalId principalId = new HttpSessionPrincipalId();
                    principalId.setId(ssid);
                    principalId.setPrincipal(principalName);

                    principal.setId(principalId);
                    principal.setAlias(principalAlias);
                    principal.setSessionId(ssid);
                    principal.setPrincipal(principalName);

                    httpSessionPrincipalsRepository.save(principal);

                    session.setAlias(principalAlias);
                    session.setPrincipal(principalName);
                    sessionRepository.save(session);

                } else {

                    session = new HttpSessionDetails();
                    session.setId(ssid);
                    session.setAlias("0");
                    session.setPrincipal(userInfo.getUsername());
                    sessionRepository.save(session);

                }
            }

        }

        private void setupSessionAttributes(SignedUserInfoCookie ssidCookie) {
            request.getSession().setAttribute("ssid", ssidCookie.getSSID());
        }
    }

}