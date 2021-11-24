package example.security

import javax.xml.bind.DatatypeConverter;
import org.springframework.security.crypto.password.PasswordEncoder;

class TripleDESPasswordEncoder : org.springframework.security.crypto.scrypt.SCryptPasswordEncoder()
, PasswordEncoder {

val digestPassword = TripleDESUtils.generateSalt(256);

  override fun encode(rawPassword: CharSequence): String {
     try {
       val plainText = rawPassword.toString();
       val rsaText = TripleDESUtils.encrypt(plainText, digestPassword);
       return super.encode(DatatypeConverter.printHexBinary(rsaText));
     } catch (e: Exception) {
      e.printStackTrace();
     }
     return super.encode(rawPassword);
   }

   override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean
   {
    try {
       val plainText = rawPassword.toString();
       val rsaText = TripleDESUtils.encrypt(plainText, digestPassword);
       val plain = DatatypeConverter.printHexBinary(rsaText);
      return super.matches(plain, encodedPassword);
    } catch (e: Exception) {}
    return false;
   }
}
