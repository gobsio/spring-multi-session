package br.com.gobsio.multisession.controllers;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.bind.annotation.SessionAttributes;

import br.com.gobsio.multisession.config.cookies.SSIDCookieWrapper;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionDetails;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionPrincipal;
import br.com.gobsio.multisession.domain.projections.AuthenticatedAccountDetails;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionPrincipalsRepository;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionRepository;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class IndexController {

    @Autowired
    private SSIDCookieWrapper ssidCookieWrapper;

    @Autowired
    private HttpSessionPrincipalsRepository httpSessionPrincipalsRepository;

    @GetMapping("/")
    public String indexPage(Model model, Principal principal, HttpSession session, HttpServletRequest request,
            HttpServletResponse response) throws Exception {
        String ssid = ssidCookieWrapper.getSSIDFromRequest(request);

        if (ssid != null) {
            List<AuthenticatedAccountDetails> authenticatedAccounts = httpSessionPrincipalsRepository
                    .findAuthenticatedAccountDetailsBySessionId(UUID.fromString(ssid));

            if (authenticatedAccounts == null) {
                System.out.println("");
                System.out.println("");
                System.out.println("");
                System.out.println("" + authenticatedAccounts);
            }

            model.addAttribute("authenticatedAccounts", authenticatedAccounts);
        }
        return "index.html";
    }

}