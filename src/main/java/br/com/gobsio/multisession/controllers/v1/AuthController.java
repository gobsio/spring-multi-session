package br.com.gobsio.multisession.controllers.v1;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.gobsio.multisession.domain.httpsession.HttpSessionDetails;
import br.com.gobsio.multisession.domain.httpsession.HttpSessionPrincipal;
import br.com.gobsio.multisession.domain.projections.AuthenticatedAccountDetails;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionPrincipalsRepository;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionRepository;
import br.com.gobsio.multisession.services.security.SecurityService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/oauth")
public class AuthController {

    @Autowired
    private SecurityService securityService;

    @Autowired
    private HttpSessionPrincipalsRepository httpSessionPrincipalsRepository;

    @GetMapping("/userinfo")
    public ResponseEntity<Principal> oauthUserinfo(Principal principal) throws Exception {
        return ResponseEntity.ok(principal);
    }

    @PostMapping("/{oauthuser}/logout")
    public String oauthUserLogout(@PathVariable("oauthuser") String oauthUser, Model model, HttpServletRequest request,
            HttpServletResponse response, Principal principal) throws Exception {
        if (securityService.logoutOAuthUser(oauthUser, request)) {
            return "redirect:/logout";
        }
        return "redirect:/";
    }

    @GetMapping("/authorize/oauthchooseaccount")
    public String oauthChooseAccount(Model model, HttpServletRequest request, HttpServletResponse response,
            Principal principal) throws Exception {
        String ssid = securityService.getSSIDFromRequest(request);

        if (ssid != null) {
            // session principals with user details (*)
            List<AuthenticatedAccountDetails> authenticatedAccounts = httpSessionPrincipalsRepository
                    .findAuthenticatedAccountDetailsBySessionId(UUID.fromString(ssid));

            model.addAttribute("authenticatedAccounts", authenticatedAccounts);
        }

        return "oauth/oauthchooseaccount.html";
    }

    @PostMapping("/authorize/oauthchooseaccount")
    public String oauthChooseAccountForm(@RequestParam("oauthuser") String oauthUser, Model model,
            HttpServletRequest request, HttpServletResponse response, Principal principal) throws Exception {
        String queryString = request.getQueryString();

        List<String> oauthRequestParams = Arrays.asList("client_id", "response_type", "redirect_uri");

        this.securityService.switchOAuthUser(oauthUser, request);

        if (request.getParameterMap().keySet().containsAll(oauthRequestParams)) {
            return "redirect:/oauth/authorize?" + queryString;
        }

        return "redirect:/oauth/authorize/oauthchooseaccount";
    }
    //

}
