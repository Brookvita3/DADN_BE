package com.example.QLNK.mapper;

import com.example.QLNK.DTOS.user.RegisterUserDTO;
import com.example.QLNK.model.User;
import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.springframework.security.crypto.password.PasswordEncoder;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "password", source = "password", qualifiedByName = "encodePassword")
    User registerUserDTOToUser(RegisterUserDTO registerUserDTO, @Context PasswordEncoder passwordEncoder);

    @Named("encodePassword")
    default String encodePassword(String password, @Context PasswordEncoder passwordEncoder) {
        return passwordEncoder.encode(password);
    }
}
