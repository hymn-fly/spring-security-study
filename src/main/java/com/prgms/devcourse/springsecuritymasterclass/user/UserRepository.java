package com.prgms.devcourse.springsecuritymasterclass.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    @Query("select u from User u join fetch u.group g left join fetch g.permissions gp join fetch gp.permission where u.username= :username")
    Optional<User> findByUsername(String username);

    @Query("select u from User u join fetch u.group g left join fetch g.permissions gp join fetch gp.permission where u.provider= :provider and u.providerId = :providerId")
    Optional<User> findByProviderAndProviderId(String provider, String providerId);
}
