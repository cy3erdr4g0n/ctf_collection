import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EnigmaCipher {

    private static final String CIPHER_ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 10000;
    private static final int KEY_SIZE = 256;

    private static SecretKey generateSecretKey(String password, byte[] salt) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        SecretKey tempKey = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(tempKey.getEncoded(), CIPHER_ALGORITHM);
    }

    private static String encryptText(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) {
        String topSecretMessage = "";
        String secretPassphrase = "abcctf2023ishere";
        byte[] secretSalt = "saltval".getBytes(StandardCharsets.UTF_8);

        try {
            SecretKey secretKey = generateSecretKey(secretPassphrase, secretSalt);
            String encryptedMessage = encryptText(topSecretMessage, secretKey);
            System.out.println("Encoded Message: " + encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

