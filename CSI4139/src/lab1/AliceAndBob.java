package lab1;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AliceAndBob {
	
//	File = m
//	Alice will Hash(m) = h
//	then Sign h using her PRAlice(h) = s
//	then generate symmetric key k
//	then compute Ek(m) = c
//	then compute EPUBob(k) = k’
//	and then send to Bob (c, k’, s)

//	Bob will need to compute DPRBob(k’) = k
//	then compute Dk(c) = m
//	then compute Hash(m) = h1
//	then compute PUAlice(s) = h2 this is the signature verification algorithm
//	and then will check if h1 = h2. 
//	If so he will know that this file came from Alice.

	public static void main(String[] args) {
		
		test();
		
		// // Using AES single key encryption
		// String password = "mypassword";
		// String passwordEnc = AES.encrypt(password);
		// String passwordDec = AES.decrypt(passwordEnc);
		//
		// System.out.println("Plain Text : " + password);
		// System.out.println("Encrypted Text : " + passwordEnc);
		// System.out.println("Decrypted Text : " + passwordDec);

//		try {
//
//			// Check if the pair of keys are present else generate those.
//			if (!RSA.areKeysPresent()) {
//				// Generates a key pair using the RSA and stores
//				// it in their respective files
//				RSA.generateKey();
//			}
//
//			final String originalText = "Text to be encrypted ";
//			ObjectInputStream inputStream = null;
//
//			// Encrypt the string using the public key
//			inputStream = new ObjectInputStream(new FileInputStream(RSA.PUBLIC_KEY_FILE));
//			final PublicKey publicKey = (PublicKey) inputStream.readObject();
//			final byte[] cipherText = RSA.encrypt(originalText, publicKey);
//
//			// Decrypt the cipher text using the private key.
//			inputStream = new ObjectInputStream(new FileInputStream(RSA.PRIVATE_KEY_FILE));
//			final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
//			final String plainText = RSA.decrypt(cipherText, privateKey);
//
//			// Printing the Original, Encrypted and Decrypted Text
//			System.out.println("Original: " + originalText);
//			System.out.println("Encrypted: " + cipherText.toString());
//			System.out.println("Decrypted: " + plainText);
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}

	}

	// private static String fileToString(String path) throws IOException {
	// String fileString = "";
	// String currentLine;
	// File langFile = new File(path);
	//
	// if (langFile.exists()){
	// BufferedReader brL = new BufferedReader(new FileReader(
	// path));
	// while ((currentLine = brL.readLine()) != null) {
	// fileString += currentLine + "\n";
	// }
	// brL.close();
	// } else {
	// System.out.println("File does not exist.");
	// }
	// return fileString;
	// }
	
	public static void test(){
		
		// testing hash string to string
		System.out.println("---- Hashing a string ----");
		String s = "my text";
		System.out.println("String: " + s);
		System.out.println("Hash: " + Hash.hashStringToString(s));
		System.out.println();
		
		// testing hash file to string
		System.out.println("---- Hashing a file to a string ----");
//		 String path = "resources/PlainText.txt";
//		 System.out.println(Hash.hashFileToString(path));//, "resources/PlainTextHashed.txt"));
		// String path2 = "/Users/karensaroc/Dropbox/OttawaU
		// Studies/CSI4139C/Labs/PlainText2.txt";
		// System.out.println(hashing(path2));
		// System.out.println();
		//
		// System.out.println(isItAMach(hashing(path1), hashing(path2)));
		// }

		
	}

}
