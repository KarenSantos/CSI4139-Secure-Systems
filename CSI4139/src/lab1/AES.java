package lab1;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;

public class AES {

	/**
	 * The Algorithm used for the key generation and for the cipher algorithm.
	 */
	private static final String ALGORITHM = "AES";

	/**
	 * The byte array that will be used to generate the secret key.
	 */
	private static final byte[] keyValue = new byte[] { 'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't',
			'K', 'e', 'y' };

	/**
	 * Encrypts a string with the generated secret key.
	 * 
	 * @param Data
	 *            The string to be encrypted.
	 * @return The String with the encrypted data.
	 * @throws Exception
	 */
	public static String encrypt(String Data) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGORITHM);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] dataBytes = c.doFinal(Data.getBytes());
		String encryptedValue = new BASE64Encoder().encode(dataBytes);
		return encryptedValue;
	}

	/**
	 * Decrypts data with the generated secret key.
	 * 
	 * @param encryptedData
	 *            The data to be decrypted.
	 * @return The String with the decrypted data.
	 * @throws Exception
	 */
	public static String decrypt(String encryptedData) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGORITHM);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
		byte[] decValue = c.doFinal(decordedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}

	/**
	 * Generates a Key with the final byte array and the algorithm specified.
	 * 
	 * @return The Key generated.
	 * @throws Exception
	 */
	private static Key generateKey() throws Exception {
		Key key = new SecretKeySpec(keyValue, ALGORITHM);
		return key;
	}

	/**
	 * Generates a Key with the input string using the specified Algorithm.
	 * 
	 * @param secKey
	 *            The string used to generate the key.
	 * @return The Key generated.
	 * @throws Exception
	 */
	private Key generateKeyFromString(final String secKey) throws Exception {
		final byte[] keyVal = new BASE64Decoder().decodeBuffer(secKey);
		final Key key = new SecretKeySpec(keyVal, ALGORITHM);
		return key;
	}

}
