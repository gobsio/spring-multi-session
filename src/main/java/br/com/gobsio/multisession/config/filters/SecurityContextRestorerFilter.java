package br.com.gobsio.multisession.config.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Adds the authentication information to the SecurityContext. Needed to allow
 * access to restricted paths after a successful authentication redirects back
 * to the application. Without it, the filter
 * {@link org.springframework.security.web.authentication.AnonymousAuthenticationFilter}
 * cannot find a user and rejects access, redirecting to the login page again.
 */
public class SecurityContextRestorerFilter extends OncePerRequestFilter {

    private UserInfoRestTemplateFactory userInfoRestTemplateFactory;

    private ResourceServerTokenServices userInfoTokenServices;

    public SecurityContextRestorerFilter(UserInfoRestTemplateFactory userInfoRestTemplateFactory,
                                         ResourceServerTokenServices userInfoTokenServices) {
        this.userInfoRestTemplateFactory = userInfoRestTemplateFactory;
        this.userInfoTokenServices = userInfoTokenServices;
    }

    @Override
    public void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws IOException, ServletException {
        try {
            final OAuth2AccessToken authentication = userInfoRestTemplateFactory.getUserInfoRestTemplate()
                    .getOAuth2ClientContext().getAccessToken();
            if (authentication != null && authentication.getExpiresIn() > 0) {
                OAuth2Authentication oAuth2Authentication = userInfoTokenServices
                        .loadAuthentication(authentication.getValue());
                SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication);
                // log.debug("Added token authentication to security context");
            } else {
                // log.debug("Authentication not found.");
            }
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}