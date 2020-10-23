package br.com.gobsio.multisession.domain.projections;

import java.util.UUID;

public interface AuthenticatedAccountDetails {
    
    // public UUID getSessionId();

    public String getAlias();

    public String getUsername();

    public String getAvatar();
    
    public String getFirstName();

    public String getLastName();

}
