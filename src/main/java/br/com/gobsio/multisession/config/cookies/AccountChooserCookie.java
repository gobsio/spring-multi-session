package br.com.gobsio.multisession.config.cookies;

import javax.servlet.http.Cookie;

public class AccountChooserCookie extends Cookie {

    private static final long serialVersionUID = 1L;

    /**
     * Name of the cookie contaning the acount chooser information.
     */
    public static final String NAME = "ACCOUNT_CHOOSER";

    public AccountChooserCookie() {
        super(NAME, "");
    }

}