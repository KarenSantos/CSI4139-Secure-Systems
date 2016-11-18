package lab1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import sun.misc.*;
//import org.apache.commons.codec.binary.Base64;

public class AES {

	/**
	 * The Algorithm used for the key generation and for the cipher algorithm.
	 */
	private static final String ALGORITHM = "AES";

	/**
	 * The byte array that will be used to generate the secret key.
	 */
	private byte[] keyValue;

	private Key key;

	/**
	 * Creates a secret symmetric key based on the specified byte array.
	 * 
	 * @param keyValueBytes
	 *            The byte array to be used to generate the key.
	 */
	public AES(byte[] keyValueBytes) {
		keyValue = keyValueBytes;
		key = generateKey();
	}

	/**
	 * Returns the symmetric key.
	 * 
	 * @return The symmetric key.
	 */
	public Key getKey() {
		return key;
	}

	// TODO Careful with this method!
	public String keyToString() {
		String stringKey = "";
		if (key != null) {
			stringKey = Base64.encode(key.getEncoded());
		}
		return stringKey;
	}

	/**
	 * Encrypts a string with the generated secret key.
	 * 
	 * @param data
	 *            The string to be encrypted.
	 * @return The String with the encrypted data.
	 * @throws Exception
	 */
	public String encryptStringToString(String data) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGORITHM);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] dataBytes = c.doFinal(data.getBytes());
		String encryptedValue = new BASE64Encoder().encode(dataBytes);
		return encryptedValue;
	}

	/**
	 * Encrypts the data in a file with the generated secret key.
	 * 
	 * @param filePath
	 *            The file with the data to be encrypted.
	 * @return The File with the encrypted data.
	 * @throws Exception
	 */
	public File encryptFileToFile(String filePath, String fileOutputPath) {
		Key key = null;
		String encryptedValue = null;
		try {
			key = generateKey();
			Cipher c = Cipher.getInstance(ALGORITHM);
			c.init(Cipher.ENCRYPT_MODE, key);
			byte[] dataBytes = c.doFinal(fileToString(filePath).getBytes());
			encryptedValue = new BASE64Encoder().encode(dataBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return stringToFile(fileOutputPath, encryptedValue);
	}

	/**
	 * Decrypts data with the generated secret key.
	 * 
	 * @param encryptedData
	 *            The data to be decrypted.
	 * @return The String with the decrypted data.
	 */
	public String decryptStringToString(String encryptedData) {
		Key key = null;
		String decryptedValue = null;
		try {
			key = generateKey();
			Cipher c = Cipher.getInstance(ALGORITHM);
			c.init(Cipher.DECRYPT_MODE, key);
			byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
			byte[] decValue = c.doFinal(decordedValue);
			decryptedValue = new String(decValue);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedValue;
	}

	/**
	 * Generates a Key with the final byte array and the algorithm specified.
	 * 
	 * @return The Key generated.
	 */
	private Key generateKey() {
		Key key = new SecretKeySpec(keyValue, ALGORITHM);
		return key;
	}

	// /**
	// * Generates a Key with the input string using the specified Algorithm.
	// *
	// * @param secKey
	// * The string used to generate the key.
	// * @return The Key generated.
	// * @throws Exception
	// */
	// private Key generateKeyFromString(final String secKey) throws Exception {
	// final byte[] keyVal = new BASE64Decoder().decodeBuffer(secKey);
	// final Key key = new SecretKeySpec(keyVal, ALGORITHM);
	// return key;
	// }

	/**
	 * Takes a file and turns it into a string.
	 * 
	 * @param path
	 *            The path of the file.
	 * @return The string with the content of the file or null the the file
	 *         doesn't exist.
	 * @throws IOException
	 */
	private static String fileToString(String path) throws IOException {
		String fileString = null;
		String currentLine;
		File file = new File(path);

		if (file.exists()) {
			BufferedReader brL = new BufferedReader(new FileReader(path));
			while ((currentLine = brL.readLine()) != null) {
				fileString += currentLine + "\n";
			}
			brL.close();
		}
		return fileString;
	}

	/**
	 * Takes a string and puts it in a text file.
	 * 
	 * @param path
	 *            The path of the new file.
	 * @param text
	 *            The string to be put in the file.
	 * @return The file created with the string.
	 */
	private static File stringToFile(String path, String text) {

		File file = new File(path);
		try {

			// Create files to store public and private key
			if (file.getParentFile() != null) {
				file.getParentFile().mkdirs();
			}
			file.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(file));
			os.writeObject((Object) text);
			os.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
		return file;
	}

}
