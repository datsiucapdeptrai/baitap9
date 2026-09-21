package vn.iostart.productmanagement.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import vn.iostart.productmanagement.dto.auth.RegisterRequest;
import vn.iostart.productmanagement.entity.Role;
import vn.iostart.productmanagement.entity.UserAccount;
import vn.iostart.productmanagement.repository.RoleRepository;
import vn.iostart.productmanagement.repository.UserAccountRepository;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {

    private final UserAccountRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserAccount register(
            RegisterRequest request
    ) {
        String username = request.getUsername().trim();
        String email = request.getEmail()
                .trim()
                .toLowerCase();
        String fullName = request.getFullName().trim();

        if (!request.getPassword().equals(
                request.getConfirmPassword()
        )) {
            throw new IllegalArgumentException(
                    "Mật khẩu xác nhận không khớp"
            );
        }

        if (userRepository.existsByUsernameIgnoreCase(
                username
        )) {
            throw new IllegalArgumentException(
                    "Username đã được sử dụng"
            );
        }

        if (userRepository.existsByEmailIgnoreCase(
                email
        )) {
            throw new IllegalArgumentException(
                    "Email đã được sử dụng"
            );
        }

        Role userRole = roleRepository
                .findByName("ROLE_USER")
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Không tìm thấy ROLE_USER"
                        )
                );

        UserAccount user = UserAccount.builder()
                .username(username)
                .email(email)
                .fullName(fullName)
                .password(
                    passwordEncoder.encode(
                        request.getPassword()
                    )
                )
                .enabled(true)
                .role(userRole)
                .build();

        return userRepository.save(user);
    }
}