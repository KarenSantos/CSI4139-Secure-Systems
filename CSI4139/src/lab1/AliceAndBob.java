package lab1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class AliceAndBob {

	private static final String ALICE_KEY = "AliceKey";
	private static final String BOB_KEY = "BobKey";
	private static final String PLAIN_TEXT_PATH = "resources/source/PlainText.txt";
	private static final String HASHED_TEXT_PATH = "resources/results/HashedText.txt";
	private static final String SIGNATURE_ALICE = "resources/results/AliceSignature.txt";
	private static final String SYM_ENCRYPTED_TEXT_PATH = "resources/results/SymEncryptedText.txt";
	private static final String ENCRYPTED_SYM_KEY = "resources/results/EncryptedSymKey.txt";

	private final static byte[] SYM_VALUE = new byte[] { 'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e',
			't', 'K', 'e', 'y' };

	// File = m
	// Alice will Hash(m) = h
	// then Sign h using her PRAlice(h) = s
	// then generate symmetric key k
	// then compute Ek(m) = c
	// then compute EPUBob(k) = k’
	// and then send to Bob (c, k’, s)

	// Bob will need to compute DPRBob(k’) = k
	// then compute Dk(c) = m
	// then compute Hash(m) = h1
	// then compute PUAlice(s) = h2 this is the signature verification algorithm
	// and then will check if h1 = h2.
	// If so he will know that this file came from Alice.

	public static void main(String[] args) throws IOException {

		// Generating key pair for Alice
		System.out.println("Generating key pair for Alice.\n");
		RSA rsaAlice = new RSA(ALICE_KEY);
		// System.out.println(fileToString("resources/keys/private_AliceKey.key"));

		// Generating key pair for Bob
		System.out.println("Generating key pair for Bob.\n");
		RSA rsaBob = new RSA(BOB_KEY);
		// System.out.println(fileToString("resources/keys/private_BobKey.key"));

		// Alice hashing the file
		System.out.println("Alice hashing text.\n");
		Hash.hashFileToFile(PLAIN_TEXT_PATH, HASHED_TEXT_PATH);
		// System.out.println(fileToString(HASHED_TEXT_PATH));

		// Alice signing the hashed file
		System.out.println("Alice signing hashed text.\n");
		rsaAlice.sign(HASHED_TEXT_PATH);
		// System.out.println(fileToString(SIGNATURE_ALICE));

		// Alice is encrypting PlainText with symmetric key
		System.out.println("Alice is encrypting text with a symmetric key.\n");
		AES aesAlice = new AES(SYM_VALUE);
		// System.out.println(aesAlice.getKey().toString() + "\n");
		aesAlice.encryptFileToFile(PLAIN_TEXT_PATH, SYM_ENCRYPTED_TEXT_PATH);
		// System.out.println(fileToString(SYM_ENCRYPTED_TEXT_PATH));

		// Alice using Bob's Public Key to Encrypt her Symmetric Key
		System.out.println("Alice encrypts her symmetric key with Bob's Public key.\n");
		rsaAlice.encryptFileToFile(aesAlice.keyToString(), rsaBob.getPublicKey(), ENCRYPTED_SYM_KEY);
		// System.out.println(fileToString(ENCRYPTED_SYM_KEY));

		System.out.println("\n ---- SENDING FILES TO BOB ----\n");

		// Bob decrypting Alice's symmetric key with his Private Key
		System.out.println("Bob decrypts Alice's symmetric key with his Private Key.\n");
		String encodedKey = rsaBob.decryptFile(ENCRYPTED_SYM_KEY);
		System.out.println(encodedKey);

		// // decode the base64 encoded string
		// byte[] decodedKey = Base64.decode(fileToString(path))
		//
		// .getDecoder().decode(encodedKey);
		// // rebuild key using SecretKeySpec
		// SecretKey originalKey = new SecretKeySpec(decodedKey, 0,
		// decodedKey.length, "AES");
		//
		// Key symKey = new Key();

		// // Bob decrypts message with Alices symmetric key
		// System.out.println("Bob decrypts the encrypted text with Alice's
		// symmetric key.\n");
		// String dec =
		// aesAlice.decryptStringToString(fileToString(SYM_ENCRYPTED_TEXT_PATH));
		//
		// // Bob hashing the decrypted message
		// System.out.println("Bob hashing the decrypted message.\n");
		// Hash.hashFileToFile(PLAIN_TEXT_PATH, "resources/HashedText2.txt");
		//
		// // Bob using Alices's PK to verify signature on Hashed text
		// System.out.println("Bob verifies the signature on the hashed
		// file.\n");
		// System.out.println("Signature verified: " + true);
	}

	public static void RSATest() {

		RSA rsaAlice = new RSA(ALICE_KEY);
		RSA rsaBob = new RSA(BOB_KEY);
		String encrypted = rsaAlice.encrypt("my text to be encrypted", rsaBob.getPublicKey()).toString();
		
		
	}

	public static void hashTest() {

		// testing hash string to string
		System.out.println("---- Hashing a string ----");
		String s = "my text";
		System.out.println("String: " + s);
		System.out.println("Hash: " + Hash.hashStringToString(s));
		System.out.println();

		// testing hash file to string
		System.out.println("---- Hashing a file to a string ----");
		String path = "resources/PlainText.txt";
		System.out.println("File: " + path);
		System.out.println("Hash: " + Hash.hashFileToString(path));
		System.out.println();

		// testing hash file to file
		System.out.println("---- Hashing a file to another file ----");
		path = "resources/PlainText.txt";
		System.out.println("File: " + path);
		String hashedFile = "resources/PlainTextHashed.txt";
		System.out.println("Hash File: " + Hash.hashFileToFile(path, hashedFile));
		System.out.println();

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

	private void testing() {

		// System.out.println(fileToString("resources/keys/private_AliceKey.key"));
		// System.out.println(fileToString("resources/keys/private_BobKey.key"));

		// // Using AES single key encryption
		// String password = "mypassword";
		// String passwordEnc = AES.encrypt(password);
		// String passwordDec = AES.decrypt(passwordEnc);
		//
		// System.out.println("Plain Text : " + password);
		// System.out.println("Encrypted Text : " + passwordEnc);
		// System.out.println("Decrypted Text : " + passwordDec);

		// try {
		//
		// // Check if the pair of keys are present else generate those.
		// if (!RSA.areKeysPresent()) {
		// // Generates a key pair using the RSA and stores
		// // it in their respective files
		// RSA.generateKey();
		// }
		//
		// final String originalText = "Text to be encrypted ";
		// ObjectInputStream inputStream = null;
		//
		// // Encrypt the string using the public key
		// inputStream = new ObjectInputStream(new
		// FileInputStream(RSA.PUBLIC_KEY_FILE));
		// final PublicKey publicKey = (PublicKey) inputStream.readObject();
		// final byte[] cipherText = RSA.encrypt(originalText, publicKey);
		//
		// // Decrypt the cipher text using the private key.
		// inputStream = new ObjectInputStream(new
		// FileInputStream(RSA.PRIVATE_KEY_FILE));
		// final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
		// final String plainText = RSA.decrypt(cipherText, privateKey);
		//
		// // Printing the Original, Encrypted and Decrypted Text
		// System.out.println("Original: " + originalText);
		// System.out.println("Encrypted: " + cipherText.toString());
		// System.out.println("Decrypted: " + plainText);
		//
		// } catch (Exception e) {
		// e.printStackTrace();
		// }
	}

}
