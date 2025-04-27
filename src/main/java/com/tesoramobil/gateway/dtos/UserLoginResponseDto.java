package com.tesoramobil.gateway.dtos;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserLoginResponseDto {

	
	private Long idUser;
	   
    private String username;

 
    private String email;

    
    private Role role;

    
    private String tkn;

}
