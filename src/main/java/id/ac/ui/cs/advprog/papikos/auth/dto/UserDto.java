package id.ac.ui.cs.advprog.papikos.auth.dto;

   import id.ac.ui.cs.advprog.papikos.auth.model.Role;
   import id.ac.ui.cs.advprog.papikos.auth.model.UserStatus;
   import lombok.AllArgsConstructor;
   import lombok.Builder;
   import lombok.Data;
   import lombok.NoArgsConstructor;

   import java.util.UUID;

   @Data
   @Builder
   @NoArgsConstructor
   @AllArgsConstructor
   public class UserDto {
       private UUID userId; // Changed type to UUID
       private String email;
       private Role role;
       private UserStatus status;
   }