package br.com.gobsio.multisession.repositories.httpsession;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.gobsio.multisession.domain.httpsession.HttpSessionDetails;

@Repository
public interface HttpSessionRepository extends JpaRepository<HttpSessionDetails, UUID> {

}
