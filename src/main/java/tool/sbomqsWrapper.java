package tool;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;

public class sbomqsWrapper extends Tool implements ITool {
    private static final Logger LOGGER = LoggerFactory.getLogger(sbomqsWrapper.class);
    public sbomqsWrapper() {
        super("sbomqs", null);
    }

    // Methods
    /**
     * @param projectLocation The path to a binary file for the desired solution of project to
     *             analyze
     * @return The path to the analysis results file
     */
    @Override
    public Path analyze(Path projectLocation) {
        LOGGER.info("sbomqs analyzing "+ projectLocation.toString());
        File tempResults = new File(System.getProperty("user.dir") + "/out/sbomqs.txt");
        tempResults.delete(); // clear out the last output. May want to change this to rename rather than delete.
        tempResults.getParentFile().mkdirs();

        Properties prop = PiqueProperties.getProperties();
        String pathTosbomqs = prop.getProperty("sbomqs.location");

        String[] cmd = {pathTosbomqs,
                "score",
                "--json",
                projectLocation.toAbsolutePath().toString()};
        LOGGER.info(Arrays.toString(cmd));
        try {
            String results = helperFunctions.getOutputFromProgram(cmd,LOGGER);
            JSONObject jsonResults = new JSONObject(results);
            int componentCount = jsonResults.getJSONArray("files").getJSONObject(0).getInt("num_components");

            BufferedWriter writer = new BufferedWriter(new FileWriter(tempResults));
            writer.write(componentCount);
            writer.close();
        } catch (IOException  e) {
            LOGGER.error("Failed to run sbomqs");
            LOGGER.error(e.toString());
            e.printStackTrace();
        } catch (JSONException e) {
            LOGGER.error("Failed to save sbomqs results");
            LOGGER.error(e.toString());
            e.printStackTrace();
        }
        return tempResults.toPath();
    }

    /**
     * parses output of tool from analyze().
     *
     * @param toolResults location of the results, output by analyze()
     * @return A Map<String,Diagnostic> with findings from the tool attached. Returns null if tool failed to run.
     */
    @Override
    public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
        return null;
    }

    /**
     * Initializes the tool by installing it through python pip from the command line.
     */
    @Override
    public Path initialize(Path toolRoot) {
        final String[] cmd = {"sbomqs", "version"};

        try {
            helperFunctions.getOutputFromProgram(cmd, LOGGER);
        } catch (IOException e) {
            e.printStackTrace();
            LOGGER.error("Failed to initialize " + this.getName());
            LOGGER.error(e.getStackTrace().toString());
        }

        return toolRoot;
    }


    //maps low-critical to numeric values based on the highest value for each range.
    private Integer severityToInt(String severity) {
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
