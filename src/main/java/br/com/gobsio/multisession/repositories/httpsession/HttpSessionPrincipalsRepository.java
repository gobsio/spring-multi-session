package br.com.gobsio.multisession.repositories.httpsession;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import br.com.gobsio.multisession.domain.httpsession.HttpSessionPrincipal;
import br.com.gobsio.multisession.domain.projections.AuthenticatedAccountDetails;

// public interface AuthentiacatedAccountDetails {
    
//     public String getSessionId();

//     public String getAlias();

//     public String getUsername();
    
//     public String getFirstName();

//     public String getLastName();

// }


@Repository // @formatter:off
public interface HttpSessionPrincipalsRepository extends JpaRepository<HttpSessionPrincipal, UUID> {

    List<HttpSessionPrincipal> findBySessionId(UUID sessionId);

    HttpSessionPrincipal findBySessionIdAndAlias(UUID sessionId, String alias);

    //
    //
    @Query(value = " select                                                   " + 
                   "   session_principal.alias as alias,                      " + 
                   "   session_principal.principal_name as username,          " + 
                   "   _user.avatar as avatar,                                 " + 
                   "   _user.first_name as firstName,                          " + 
                   "   _user.last_name as lastName                             " + 
                   " from http_session_principals session_principal           " + 
                   "   inner join users _user                                  " + 
                   "     on session_principal.principal_name = _user.username  " + 
                   " where session_principal.session_id = :sessionId          ", nativeQuery = true)
    List<AuthenticatedAccountDetails> findAuthenticatedAccountDetailsBySessionId(UUID sessionId);


}
