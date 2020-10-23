package br.com.gobsio.multisession.repositories.users;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import br.com.gobsio.multisession.domain.users.User;

@Repository
public interface UserRepository extends JpaRepository<User, BigInteger> {

    @Query(value = "SELECT u.* FROM users u WHERE LOWER(u.username) = LOWER(:username)", nativeQuery = true)
    Optional<User> findByUsername(@Param("username") String username);

    @Query(value = "SELECT ua.authority FROM authorities a WHERE a.username = :username", nativeQuery = true)
    Set<String> fetchAuthoritiesByUsername(@Param("username") String username);

}
