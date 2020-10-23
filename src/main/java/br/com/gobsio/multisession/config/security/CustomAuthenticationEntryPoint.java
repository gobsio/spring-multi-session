package br.com.gobsio.multisession.config.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        String clientId = request.getParameter("client_id");
        String redirectUrl = "/login";
        HttpSession session = request.getSession();
        // session.setAttribute(SessionSaveAttribute.CLIENT_ID_ATR, clientId);
        // echoSessionAtr(request);
        redirectStrategy.sendRedirect(request, response, redirectUrl);
    }

}