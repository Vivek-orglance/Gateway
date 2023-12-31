package co.nz.csoft.bookonegateway.repository;

import co.nz.csoft.bookonegateway.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    User findByName(String username);
}
