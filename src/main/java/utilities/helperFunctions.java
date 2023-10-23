/**
 * MIT License
 * Copyright (c) 2019 Montana State University Software Engineering Labs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package utilities;

import java.io.*;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.model.Diagnostic;
import pique.model.ModelNode;
import pique.model.QualityModel;
import pique.model.QualityModelImport;
import pique.utility.PiqueProperties;

/**
 * Collection of common helper functions used across the project.
 *
 * @author Andrew Johnson and Eric O'Donoghue
 */
public class helperFunctions {
	private static final Logger LOGGER = LoggerFactory.getLogger(helperFunctions.class);

	/**
	 * A method to check for equality up to some error bounds
	 * @param x The first number
	 * @param y	The second number
	 * @param eps The error bounds
	 * @return True if |x-y|<|eps|, or in other words, if x is within eps of y.
	 */
//	public static boolean EpsilonEquality(BigDecimal x, BigDecimal y, BigDecimal eps) {
//		BigDecimal val = x.subtract(y).abs();
//		int comparisonResult = val.compareTo(eps.abs());
//		if (comparisonResult==1) {
//			return false;
//		}
//		else {
//			return true;
//		}
//	}

	/**
	 * Given a set of CVE and/or GHSA names, returns the CWEs the vulnerabilities are associated with. Runs
	 * a python script, CVE_to_CWE.py, through the command line to achieve this.
	 *
	 * @param cveList An ArrayList<String> of one or more CVE names
	 * @return An array of CWEs associated with the given CVEs
	 */
	public static String[] getCWE(ArrayList<String> cveList, String githubTokenPath) {
		Properties prop = PiqueProperties.getProperties();
		String pathToScript = prop.getProperty("cveTocwe.location");
		String pathToNVDDict = prop.getProperty("nvd-dictionary.location");

		// Convert each cveList to a comma-separated string
		StringBuilder cveString = new StringBuilder();
		for (String entry : cveList) {
			if (cveString.length() > 0) {
				cveString.append(",");
			}
			cveString.append(entry);
		}

		// tool did not find any vulnerabilities
		if (cveString.toString().isEmpty()) {
			return new String[]{};
		}

		// command for running python script for converting vulnerabilities to CWEs
		String[] cmd = {"python3", pathToScript, "--list", cveString.toString(), "--github_token", githubTokenPath, "--nvdDict", pathToNVDDict};

		String cwe = "";
		try {
			cwe = getOutputFromProgram(cmd,LOGGER);
		} catch (IOException e) {
			System.err.println("Error running CVE_to_CWE.py");
			e.printStackTrace();
		}

		// CVE_to_CWE.py prints the results to standard out, trim the newlines and return array
        return cwe.split("\n \n");
	}

	/**
	 * Downloads the most recent version of the national vulnerability database using the NVD API.
	 * Achieves this running a python script, download_nvd.py, with the command line.
	 */
	public static void downloadNVD() {
		Properties prop = PiqueProperties.getProperties();
		String pathToScript = prop.getProperty("downloadNVD.location");
		String pathToDownloadTo = prop.getProperty("nvd-dictionary.location");
		String nvdCVECount = prop.getProperty("nvd-cve-count");
		String nvdApiKeyPath = prop.getProperty("nvd-api-key-path");

		String[] cmd = {"python3", pathToScript, pathToDownloadTo, nvdCVECount, nvdApiKeyPath};

		String result = "";
		try {
			result = getOutputFromProgram(cmd,LOGGER);
			if (result.equals("true\n")) {
				System.out.println("Successfully downloaded NVD.");
				LOGGER.info("Successfully downloaded NVD");
			}
			else {
				System.err.println("Error downloading NVD " + result);
				LOGGER.error("Error down loading NVD " + result);
			}
		} catch (IOException e) {
			System.err.println("Error running download_nvd.py");
			LOGGER.error("Error running download_nvd.py " + e);
			e.printStackTrace();
		}
	}

	/**
	 * Opens the component count results from sbomqs tool and returns the current SBOM under analysis component count.
	 *
	 * @return component count as an integer
	 */
	public static int getComponentCount() {
		try {
			File tempResults = new File(System.getProperty("user.dir") + "/out/sbomqs.txt");
			FileReader fileReader = new FileReader(tempResults);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			int componenetCount = Integer.parseInt(bufferedReader.readLine());
			bufferedReader.close();

			return componenetCount;
		}
		catch (IOException  e) {
			LOGGER.error("Failed to open sbomqs.txt could not get component count return 1");
			LOGGER.error(e.toString());
			e.printStackTrace();
			return 1;
		}
	}

	 /**
	  * Taken directly from https://stackoverflow.com/questions/13008526/runtime-getruntime-execcmd-hanging
	  * 
	  * @param program - A string as would be passed to Runtime.getRuntime().exec(program)
	  * @return the text output of the command. Includes input and error.
	  * @throws IOException
	  */
	public static String getOutputFromProgram(String[] program, Logger logger) throws IOException {
		if(logger!=null) logger.debug("Executing: " + String.join(" ", program));
	    Process proc = Runtime.getRuntime().exec(program);
	    return Stream.of(proc.getErrorStream(), proc.getInputStream()).parallel().map((InputStream isForOutput) -> {
	        StringBuilder output = new StringBuilder();
	        try (BufferedReader br = new BufferedReader(new InputStreamReader(isForOutput))) {
	            String line;
	            while ((line = br.readLine()) != null) {
	            	if(logger!=null) {
	            		logger.debug(line);
	            		System.out.println(line);
	            	}
	                output.append(line);
	                output.append("\n");
	            }
	        } catch (IOException e) {
	        	logger.error("Failed to get output of execution.");
	            throw new RuntimeException(e);
	        }
	        return output;
	    }).collect(Collectors.joining());
	}
	
	 /**
	  * Reads a given file paths contents into a string and returns the results.
	  * 
	  * @param filePath - Path of file to be read
	  * @return the text output of the file content.
	  * @throws IOException
	  */
	public static String readFileContent(Path filePath) throws IOException
    {
        StringBuilder contentBuilder = new StringBuilder();
 
        try (Stream<String> stream = Files.lines( filePath, StandardCharsets.UTF_8)) 
        {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        }
        catch (IOException e) 
        {
            throw e;
        }
 
        return contentBuilder.toString();
    }
	
	/**
	 * This function finds all diagnostics associated with a certain toolName and returns them in a Map with the diagnostic name as the key.
	 * This is used common to initialize the diagnostics for tools.
	 *
	 * @param toolName The desired tool name
	 * @return All diagnostics in the model structure with tool equal to toolName
	 */
	public static Map<String, Diagnostic> initializeDiagnostics(String toolName) {
		// load the qm structure
		Properties prop = PiqueProperties.getProperties();
		Path blankqmFilePath = Paths.get(prop.getProperty("blankqm.filepath"));
		QualityModelImport qmImport = new QualityModelImport(blankqmFilePath);
        QualityModel qmDescription = qmImport.importQualityModel();

        Map<String, Diagnostic> diagnostics = new HashMap<>();
        
        // for each diagnostic in the model, if it is associated with this tool, 
        // add it to the list of diagnostics
        for (ModelNode x : qmDescription.getDiagnostics().values()) {
        	Diagnostic diag = (Diagnostic) x;
        	if (diag.getToolName().equals(toolName)) {
        		diagnostics.put(diag.getName(),diag);
        	}
        }
       
		return diagnostics;
	}


	/**
	 * Maps low-critical to numeric values based on the highest value for each range.
	 *
	 * @param severity
	 * @return
	 */
	public static Integer severityToInt(String severity) {
		Integer severityInt = 1;
		switch(severity.toLowerCase()) {
			case "low": {
				severityInt = 4;
				break;
			}
			case "medium": {
				severityInt = 7;
				break;
			}
			case "high": {
				severityInt = 9;
				break;
			}
			case "critical": {
				severityInt = 10;
				break;
			}
		}

		return severityInt;
	}

}
