import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.util.Formatter;

public class Encryption {
    public void Encryption_Base64(String x,String y){
     String message = x;
        String key = y;
        String algorithm = "HmacSHA1";  // OPTIONS= HmacSHA512, HmacSHA256, HmacSHA1, HmacMD5
        try {
            Mac sha256_hmac = Mac.getInstance(algorithm);
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), algorithm);
             sha256_hmac.init(secret_key);
            String hash = Base64.encode(sha256_hmac.doFinal(message.getBytes("UTF-8")));
            System.out.println(hash);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        }    
    }
    private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
    }
                
    public void Encryption_Hash(String x,String y){
     String message = x;
        String key = y;
        String algorithm = "HmacSHA1";  // OPTIONS= HmacSHA512, HmacSHA256, HmacSHA1, HmacMD5
        try {
            Mac sha256_hmac = Mac.getInstance(algorithm);
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), algorithm);
             sha256_hmac.init(secret_key);
            String hash = toHexString(sha256_hmac.doFinal(message.getBytes()));
            System.out.println(hash);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        }    
    }
    public static void main(String args[]) {
        Encryption encryption = new Encryption();
        encryption.Encryption_Base64("hEx", "123456");   // hEx == > msg and 123456 == > key // it will encryption with HMAC algorithm in base64 coding 
        encryption.Encryption_Hash("hEx", "123456"); // hEx == > msg and 123456 == > key // it will encryption with HMAC algorithmin hex coding 
    }

}