package lab1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {

	/**
	 * The Algorithm used for the key generation and for the cipher algorithm.
	 */
	private static final String ALGORITHM = "SHA-256";

	/**
	 * Hashes a string using MessageDigest from java security.
	 * 
	 * @param text
	 *            The string text to be hashed.
	 * @return The hashed string or null if the message could not be hashed with
	 *         the SHA-256 algorithm.
	 */
	public static String hashStringToString(String text) {
		MessageDigest messageDigest = null;
		String hashedString = null;
		try {
			messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(text.getBytes());
			hashedString = new String(messageDigest.digest());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return hashedString;
	}

	/**
	 * Hashes the contents of a specified file using MessageDigest from java
	 * security.
	 * 
	 * @param inPath
	 *            The path of the file to be hashed.
	 * @param outPath
	 *            The path of the file with the hash.
	 * @return The hashed file or null if the file could not be created or if
	 *         the message could not be hashed with the SHA-256 algorithm.
	 */
	public static File hashFileToFile(String inPath, String outPath) {
		MessageDigest messageDigest = null;
		File hashedText = null;
		try {
			messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(fileToString(inPath).getBytes());
			hashedText = stringToFile(outPath, new String(messageDigest.digest()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return hashedText;
	}

	/**
	 * Hashes the contents of a specified file using MessageDigest from java
	 * security.
	 * 
	 * @param path
	 *            The path of the file to be hashed.
	 * @return The hashed file as a string or null if the file could not be created or if
	 *         the message could not be hashed with the SHA-256 algorithm.
	 */
	public static String hashFileToString(String path) {
		MessageDigest messageDigest = null;
		String hashedText = null;
		try {
			messageDigest = MessageDigest.getInstance(ALGORITHM);
			messageDigest.update(fileToString(path).getBytes());
			hashedText = new String(messageDigest.digest());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return hashedText;
	}
	
	/**
	 * Takes a file and turns it into a string.
	 * 
	 * @param path
	 *            The path of the file.
	 * @return The string with the content of the file or null the the file doesn't exist.
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

		// File file = new File(path);
		// file.createNewFile(); // only creates if doesn't exist yet
		//
		// try (Writer w = new BufferedWriter(
		// new OutputStreamWriter(new FileOutputStream(path), "utf-8"))) {
		// w.write(text);
		// }
		// PrintWriter writer = new PrintWriter(new BufferedWriter(new
		// FileWriter("DB/languageBD.txt", true)));
		// writer.println(language.getId() + "#$%" + language.getName());
		// writer.close();
		// return file;

		// File hashedTextFile = new File(path);
		//
		// try {
		// // Create files to store public and private key
		// if (hashedTextFile.getParentFile() != null) {
		// hashedTextFile.getParentFile().mkdirs();
		// }
		// hashedTextFile.createNewFile();
		//
		// // Saving the Private key in a file
		// ObjectOutputStream privateKeyOS;
		// privateKeyOS = new ObjectOutputStream(new
		// FileOutputStream(hashedTextFile));
		// privateKeyOS.writeObject(text);
		// privateKeyOS.close();
		// } catch (IOException e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		// return hashedTextFile;
	}

}
