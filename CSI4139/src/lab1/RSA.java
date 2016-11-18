package lab1;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;

public class RSA {

	/**
	 * Strings to hold name of the encryption algorithm.
	 */
	private static final String ALGORITHM = "RSA";
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

	private final static String PRIVATE = "resources/keys/private_";
	private final static String PUBLIC = "resources/keys/public_";
	private final static String KEY = ".key";

	private String privateKeyName;
	private String publicKeyName;
	private PrivateKey privateKey;
	private PublicKey publicKey;

	public RSA(String pairName) {
		this.privateKeyName = PRIVATE + pairName + KEY;
		this.publicKeyName = PUBLIC + pairName + KEY;
		generateKey();
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Encrypt a plain text using a specified public key.
	 * 
	 * @param text
	 *            The original plain text.
	 * @param key
	 *            The public key to be used to encrypt the text.
	 * @return The encrypted text in a byte array.
	 * @throws java.lang.Exception
	 */
	public byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Encrypt a plain text using a specified public key and returns a file with
	 * the cipher.
	 * 
	 * @param text
	 *            The original plain text to be encrypted.
	 * @param key
	 *            The public key to be used to encrypt the text.
	 * @param path
	 *            The path of the file to save the cipher.
	 * @return The encrypted text in a byte array.
	 * @throws java.lang.Exception
	 */
	public File encryptFileToFile(String text, PublicKey key, String path) {
		byte[] cipherText = null;
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return stringToFile(path, cipherText.toString());
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            The encrypted text in a byte array.
	 * @return The decrypted text as a string.
	 * @throws java.lang.Exception
	 */
	public String decrypt(byte[] text) {
		byte[] decryptedText = null;
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedText = cipher.doFinal(text);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return new String(decryptedText);
	}

	/**
	 * Decrypt content of a file using private key.
	 * 
	 * @param filePath
	 *            The path to the file to be decrypted.
	 * @return The decrypted text as a string.
	 * @throws java.lang.Exception
	 */
	public String decryptFile(String filePath) {
		byte[] decryptedText = null;
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedText = cipher.doFinal(fileToString(filePath).getBytes());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return new String(decryptedText);
	}

	/**
	 * Signs the content of a specified file with the private key of this
	 * instance.
	 * 
	 * @param dataFilePath
	 *            The path of the file to be signed.
	 * @return The file with the signature content.
	 */
	public File sign(String dataFilePath) {

		File dataFile = new File(dataFilePath);
		File signature = new File(privateKeyName);
		Signature dsa = null;
		byte[] realSig = null;

		try {
			dsa = Signature.getInstance(SIGNATURE_ALGORITHM);

			dsa.initSign(privateKey);

			// Reading the data file to sign
			FileInputStream fis = new FileInputStream(dataFile);
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = bufin.read(buffer)) >= 0) {
				dsa.update(buffer, 0, len);
			}
			;
			bufin.close();

			// Signing
			realSig = dsa.sign();

			// Putting signature in a file
			FileOutputStream output = new FileOutputStream(signature);
			output.write(realSig);
			output.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return signature;
	}

	/**
	 * Takes the file path of a signature, a file path to data, and a public key
	 * and uses the public key to decrypt the signature and compare it to the
	 * data.
	 * 
	 * @param signatureFilePath
	 *            The path of the signature file. That is the data that has been
	 *            signed.
	 * @param dataPath
	 *            The path of the data file.
	 * @param pk
	 *            The public key to decrypt the signature.
	 * @return
	 */
	public boolean verifySignature(String signatureFilePath, String dataPath, PublicKey pk) {

		FileInputStream signedData = null;
		boolean verification = false;
		try {
			// Reading the signed data
			signedData = new FileInputStream(signatureFilePath);
			byte[] sigToVerify = new byte[signedData.available()];
			signedData.read(sigToVerify);
			signedData.close();

			// creating the signature class to handle the verification
			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
			sig.initVerify(pk);

			// Reading the data
			FileInputStream datafis = new FileInputStream(dataPath);
			BufferedInputStream bufin = new BufferedInputStream(datafis);

			// Updating the Signature instance with the bytes of the data
			byte[] buffer = new byte[1024];
			int totalLength;
			while (bufin.available() != 0) {
				totalLength = bufin.read(buffer);
				sig.update(buffer, 0, totalLength);
			}

			bufin.close();

			// The Signature instance verifies if the signature matches the
			// data bytes that were uploaded
			verification = sig.verify(sigToVerify);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return verification;
	}
	
	public void testPadding() throws Exception {
	    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    KeyPair keyPair = keyGen.generateKeyPair();

	    /* constant 117 is a public key size - 11 */
	    byte[] plaintext = new byte[117];
	    random.nextBytes(plaintext);

	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
	    byte[] ciphertext = cipher.doFinal(plaintext);
	    System.out.println(plaintext.length + " becomes " + ciphertext.length);
	}

	/**
	 * Generate key which contains a pair of private and public key using 1024
	 * bytes. Store the set of keys in Prvate.key and Public.key files.
	 */
	private void generateKey() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024);
			final KeyPair key = keyGen.generateKeyPair();
			privateKey = key.getPrivate();
			publicKey = key.getPublic();

			File privateKeyFile = new File(privateKeyName);
			File publicKeyFile = new File(publicKeyName);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
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
		String fileString = "";
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
}
