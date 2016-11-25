package lab4;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.apache.commons.codec.binary.Hex;

public class Antivirus {

	final static String LAB4_PATH = "/Users/karensaroc/Dropbox/OttawaU Studies/CSI4139C/Labs/Lab4/";

	private static List<String> viruses;

	public static void main(String[] args) {

		// System.out.println(System.getProperty("user.home"));

		System.out.println("System is starting...\n");

		VirusDefinitions def = new VirusDefinitions();
		viruses = new ArrayList<>();
		viruses.addAll(def.getDefinitions());

		System.out.println("Viruses definitions up to date.\n");

		System.out.println("Enter the path for the file you would like to scann: ");

		Scanner sc = new Scanner(System.in);
		File toScan = new File(LAB4_PATH + sc.nextLine());

		while (!toScan.exists()) {
			System.out.println("The path entered is not valid. Please try again:");
			toScan = new File(LAB4_PATH + sc.nextLine());
		}
		sc.close();

		if (toScan.isDirectory()) {
			System.out.println("Preparing to scan all files in the folder '" + toScan.getName() + "'...\n");
			scanFolder(toScan);
		} else {
			System.out.println("Preparing to scan file '" + toScan.getName() + "'...\n");
			scanFile(toScan);
		}
	}

	private static void scanFile(File file) {
		String status = "Scanning file: " + file.getName();
		System.out.println(status);

		if (virusInContent(file)){
			System.err.println("    ALERT: Virus Detected in file content!");
		}
		if (virusInHash(file)) {
			System.err.println("    ALERT: Virus Detected in file code!");
		}
	}

	private static String scanFolder(File file) {
		String result = "No virus detected =)";
		File[] files = file.listFiles();
		for (File f : files) {
			if (f.isDirectory()) {
				scanFolder(f);
			} else {
				scanFile(f);
			}
		}
		return result;
	}

	private static boolean virusInContent(File file) {
		boolean found = false;
		String currentLine;
		if (file.exists()) {
			BufferedReader brL;
			try {
				brL = new BufferedReader(new FileReader(file));
				while ((currentLine = brL.readLine()) != null) {
					for (String virus : viruses){
						if (currentLine.contains(virus)){
							found = true;
						}
					}
				}
				brL.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return found;
	}

	private static boolean virusInHash(File file) {
		boolean found = false;

		MessageDigest md;
		String hash = "";
		try {
			md = MessageDigest.getInstance("MD5");
			String digest = getDigest(new FileInputStream(file), md, 2048);
			hash = digest.toUpperCase();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		for (String virus : viruses) {
			if (virus.equals(hash)) {
				found = true;
			}
		}
		return found;
	}

	private static String getDigest(InputStream is, MessageDigest md, int byteArraySize) {

		md.reset();
		byte[] bytes = new byte[byteArraySize];
		int numBytes;
		try {
			while ((numBytes = is.read(bytes)) != -1) {
				md.update(bytes, 0, numBytes);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] digest = md.digest();
		String result = new String(Hex.encodeHex(digest));
		return result;
	}
}
