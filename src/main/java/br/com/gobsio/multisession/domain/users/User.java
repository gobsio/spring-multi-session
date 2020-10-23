package br.com.gobsio.multisession.domain.users;

import java.io.Serializable;
import java.math.BigInteger;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    private BigInteger id;

    @Column(name = "username")
    private String username;
    
    private String password;

    private String firstName;

    private String lastName;

    private String phone;

    private Boolean enabled;

    private Boolean active;


}