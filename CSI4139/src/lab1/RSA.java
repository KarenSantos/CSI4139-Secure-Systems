package lab1;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
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

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            The original plain text.
	 * @return The encrypted text in a byte array.
	 * @throws java.lang.Exception
	 */
	public byte[] encrypt(String text) {
		byte[] cipherText = null;
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
		// TODO should encrypt with any PUkey
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

	public boolean verifySignature(String signatureFilePath, String dataPath, PublicKey pk) {

		FileInputStream sigfis = null;
		boolean verification = false;
		try {
			sigfis = new FileInputStream(signatureFilePath);
			byte[] sigToVerify = new byte[sigfis.available()];
			sigfis.read(sigToVerify);
			sigfis.close();

			Signature sig = Signature.getInstance(ALGORITHM);
			sig.initVerify(pk);

			FileInputStream datafis = new FileInputStream(dataPath);
			BufferedInputStream bufin = new BufferedInputStream(datafis);

			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				sig.update(buffer, 0, len);
			}
			;

			bufin.close();
			verification = sig.verify(sigToVerify);

			System.out.println("signature verifies: " + true);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return verification;
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
}
