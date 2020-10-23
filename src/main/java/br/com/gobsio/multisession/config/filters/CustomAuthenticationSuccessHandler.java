package br.com.gobsio.multisession.config.filters;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

// @Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // @Autowired
    // private ManagerFactoryParameters managerFactory;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        String userName = "";
        HttpSession session = request.getSession();

        // Collection< GrantedAuthority > authorities = null;
        if (authentication.getPrincipal() instanceof Principal) {
            userName = ((Principal) authentication.getPrincipal()).getName();
            session.setAttribute("role", "none");

            updateAccountsChooserCookie(request, response, authentication);

        } else {
            UserDetails userSpringSecu = (UserDetails) SecurityContextHolder.getContext().getAuthentication()
                    .getPrincipal();
            session.setAttribute("role", String.valueOf(userSpringSecu.getAuthorities()));
            // session.setAttribute("connectedUser",
            // managerFactory.getUserManager().findByUserName(userSpringSecu.getUsername()));
        }
        response.sendRedirect("/public/showAtlas");
    }

    private void updateAccountsChooserCookie(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        Cookie cookie = new Cookie("SSID", "teste");

        response.addCookie(cookie);
    }

}