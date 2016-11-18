package lab4;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class VirusDefinitions {

	final private String DEF_PATH = "resources/source/Signature.DAT";

	private List<String> definitions;

	public VirusDefinitions() {
		this.definitions = new ArrayList<>();
		loadDefinitions();
	}
	
	public List<String> getDefinitions(){
		return this.definitions;
	}

	private void loadDefinitions() {

		File file = new File(DEF_PATH);
		try {

			String currentLine;

			// Loading the virus definitions
			if (file.exists()) {
				BufferedReader brL = new BufferedReader(new FileReader(DEF_PATH));
				while ((currentLine = brL.readLine()) != null) {
					definitions.add(currentLine);
				}
				brL.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
