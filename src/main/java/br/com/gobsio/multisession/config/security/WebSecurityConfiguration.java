package br.com.gobsio.multisession.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import br.com.gobsio.multisession.config.cookies.CookieSecurityContextRepository;
import br.com.gobsio.multisession.config.cookies.SignedUserInfoCookie;
import br.com.gobsio.multisession.services.userdetails.UserDetailsService;

import javax.sql.DataSource;

@Order(2)
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    static final String LOGIN_FORM_URL = "/login";
    static final String TARGET_AFTER_SUCCESSFUL_LOGIN_PARAM = "redirect";
    static final String COLOUR_PARAM = "colour";

    private final DataSource dataSource;

    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    CookieSecurityContextRepository cookieSecurityContextRepository;

    @Autowired
    LoginWithTargetUrlAuthenticationEntryPoint loginWithTargetUrlAuthenticationEntryPoint;

    @Autowired
    private RedirectToOriginalUrlAuthenticationSuccessHandler redirectToOriginalUrlAuthenticationSuccessHandler;

    public WebSecurityConfiguration(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //@formatter:off
        http
            // deactivate session creation
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and().csrf().disable()
            // store SecurityContext in Cookie / delete Cookie on logout
            .securityContext()
                .securityContextRepository(cookieSecurityContextRepository)
            .and().logout().permitAll().deleteCookies(SignedUserInfoCookie.NAME)

            // deactivate RequestCache and append originally requested URL as query parameter to login form request
            .and().requestCache().disable()
            .exceptionHandling().authenticationEntryPoint(loginWithTargetUrlAuthenticationEntryPoint)

            // configure form-based login
            .and()
            .formLogin()
            .loginPage(LOGIN_FORM_URL).permitAll()
            // after successful login forward user to originally requested URL
            .successHandler(redirectToOriginalUrlAuthenticationSuccessHandler);

        // http.oauth2Login()
		// 		.authorizationEndpoint()
		// 			.authorizationRequestRepository(this.cookieAuthorizationRequestRepository());

        http
            .authorizeRequests()
                .antMatchers("/assets/**", "/css/**", "/js/**", "/images/**", "/h2-console**").permitAll();
        http
            // .addFilterAfter(new TokenCookieCreationFilter(userInfoRestTemplateFactory), AbstractPreAuthenticatedProcessingFilter.class)
            // .addFilterBefore(new SecurityContextRestorerFilter(userInfoRestTemplateFactory, userInfoTokenServices), AnonymousAuthenticationFilter.class)
            .authorizeRequests()
            // "/oauth/**", 
                .antMatchers("/login**", "/h2-console**").permitAll()
                .antMatchers("/api/**").authenticated()
                .anyRequest().authenticated();
    }



    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        if (passwordEncoder == null) {
            passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }
        return passwordEncoder;
    }

}
