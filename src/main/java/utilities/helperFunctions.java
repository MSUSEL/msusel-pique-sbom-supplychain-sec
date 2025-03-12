/*
 * MIT License
 *
 * Copyright (c) 2023 Montana State University Software Engineering Labs
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

import model.SbomQualityModelImport;
import model.SbomDiagnostic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.model.Diagnostic;
import pique.model.ModelNode;
import pique.model.ProductFactor;
import pique.model.QualityModel;
import pique.utility.BigDecimalWithContext;
import pique.utility.PiqueProperties;

/**
 * Collection of common helper functions used across the project.
 *
 * @author Andrew Johnson and Eric O'Donoghue
 */
public class helperFunctions {
	private static final Logger LOGGER = LoggerFactory.getLogger(helperFunctions.class);

	/**
	 * This function finds all diagnostics associated with a certain toolName and returns them in a Map with the diagnostic name as the key.
	 * This is used common to initialize the diagnostics for tools.
	 *
	 * @param toolName The desired tool name
	 * @return All diagnostics in the model structure with tool equal to toolName
	 */
	public static Map<String, Diagnostic> initializeDiagnostics(String toolName, String propertiesPath) throws IOException {
		// load the qm structure
		Properties prop = null;
		try {
			prop = propertiesPath == null || propertiesPath.isEmpty() ? PiqueProperties.getProperties() : PiqueProperties.getProperties(propertiesPath);
		} catch (IOException e) {
			e.printStackTrace();
		}
		Path blankqmFilePath = Paths.get(prop.getProperty("blankqm.filepath"));

		// Custom quality model import so that we can use SBOMDiagnostic
		SbomQualityModelImport qmImport = new SbomQualityModelImport(blankqmFilePath);
		QualityModel qmDescription = qmImport.importQualityModel();

		Map<String, Diagnostic> diagnostics = new HashMap<>();

		// for each diagnostic in the model, if it is associated with this tool,
		// add it to the list of diagnostics
		for (ModelNode x : qmDescription.getDiagnostics().values()) {
			Diagnostic diag = (SbomDiagnostic) x;
			if (diag.getToolName().equals(toolName)) {
				diagnostics.put(diag.getName(),diag);
			}
		}

		return diagnostics;
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

	public static String getImageName(Path projectLocation) {
		try {
			String imageName = Files.readString(projectLocation);

			return imageName;
		}
		catch (IOException e) {
			System.out.println("Failed to read image name from file: " + projectLocation);
			System.out.println("Expected input format: text file containing a single docker image in the format name:tag");
			LOGGER.error("Failed to read image name from file: {}", projectLocation);
			LOGGER.error("Expected input format: text file containing a single docker image in the format name:tag");
			LOGGER.error(e.toString());
			e.printStackTrace();
		}

		return "";
	}

	/**
	 * Maps low-critical to numeric values based on the highest value for each range.
	 *
	 * @param severity low, medium, high, or critical CVSS score
	 * @return severity as an Integer
	 */
	public static Integer severityToInt(String severity) {
		Integer severityInt = 1;
		switch(severity.toLowerCase()) {
			case "low": {
				severityInt = 1;
				break;
			}
			case "medium": {
				severityInt = 3;
				break;
			}
			case "high": {
				severityInt = 6;
				break;
			}
			case "critical": {
				severityInt = 10;
				break;
			}
		}

		return severityInt;
	}

	public static QualityModel trimBenchmarkedMeasuresWithNoFindings(QualityModel qm){
		for (ModelNode qa : qm.getQualityAspects().values()){
			recursiveRemoveAllZeroes(qa);
		}
		return qm;
	}

	public static boolean doThresholdsHaveNonZero(BigDecimal[] thresholds){
		if (thresholds != null) {
			//will be null when evaluate is called on a non measures node
			for (BigDecimal threshold : thresholds) {
				if (threshold.compareTo(BigDecimal.ZERO) != 0) {
					//found a nonZero
					return true;
				}
			}
		}
		return false;
	}

	private static boolean doThresholdsHaveNonZero(ModelNode node){
		return doThresholdsHaveNonZero(node.getThresholds());
	}

	//return children of node
	private static void recursiveRemoveAllZeroes(ModelNode node){
		boolean foundNonZero = false;
		if (node instanceof Diagnostic){
			//base case, return. We should always run into a diagnostic node
			return;
		}
		Map<String, ModelNode> newChildren = new HashMap<>();
		for (ModelNode existingChild : node.getChildren().values()){
			foundNonZero = doThresholdsHaveNonZero(existingChild);
			recursiveRemoveAllZeroes(existingChild);
			if (foundNonZero){
				//keep this node and this node's children, but still need to evaluate children
				newChildren.put(existingChild.getName(), existingChild);
			}
			if (existingChild instanceof Diagnostic){ //keep diagnostic nodes regardless; if
				newChildren.put(existingChild.getName(), existingChild);
			}
			if (existingChild instanceof ProductFactor){
				if (!existingChild.getChildren().isEmpty()) {
					//product factor's children have been retained from the recursive call
					newChildren.put(existingChild.getName(), existingChild);
				}
			}
		}
		node.setChildren(newChildren);
		Map<String, BigDecimal> newWeights = new HashMap<>();
		for (ModelNode newChild : node.getChildren().values()){
			double newWeight = 1 / (double) newChildren.size();
			newWeights.put(newChild.getName(), new BigDecimalWithContext(newWeight));
		}
		node.setWeights(newWeights);

	}
}
