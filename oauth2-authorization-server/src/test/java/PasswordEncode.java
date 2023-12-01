import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordEncode {

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println("123456 after encode: " + encoder.encode("123456"));
        System.out.println("client after encode: " + encoder.encode("secret"));
    }

}
