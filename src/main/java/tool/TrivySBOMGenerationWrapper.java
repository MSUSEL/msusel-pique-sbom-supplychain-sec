package tool;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utilities.helperFunctions;

/**
 * Provides a wrapper around the Trivy tool to generate Software Bill of Materials (SBOM) from file systems.
 * This class simplifies the process of SBOM generation by encapsulating the command line execution of Trivy,
 * handling of output paths, and logging of activities and errors.
 */
public class TrivySBOMGenerationWrapper implements IGenerationTool {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    /**
     * Initializes a new instance of the TrivySBOMGenerationWrapper class.
     */
    public TrivySBOMGenerationWrapper() {

    }

    /**
     * Generates an SBOM for a given project location using Trivy. The SBOM is created in the CycloneDX format
     * and saved to a predetermined directory under the project's root directory.
     * This method constructs the command to run Trivy with the necessary arguments to produce the SBOM,
     * executes the command, and logs the process and potential errors.
     *
     * @param projectLocation The file path of the project directory for which to generate the SBOM.
     */
    public void generate(Path projectLocation, String genTool) {
        LOGGER.info("Trivy Generation --- Generating SBOM for {}", projectLocation.toString());

        File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-trivy-cdx-" + projectLocation.getFileName() + ".json");
        String spec = "cyclonedx"; // output format

        // command for running Trivy SBOM generation on the command line
        // trivy fs --format {spec} --output {output_name.json} {file_system}

        // TODO messy if statement but can improve later
        if (genTool.contains("fs")) {
            String[] cmd = {"trivy",
                    "fs", // arg to indicate file system generation
                    "--format", spec,
                    "--output", generatedSbom.toPath().toAbsolutePath().toString(), // output path
                    projectLocation.toAbsolutePath().toString()}; // product under analysis path
            LOGGER.info(Arrays.toString(cmd));
            // runs the command built above and captures the output, trivy itself will handle the file saving
            try {
                helperFunctions.getOutputFromProgram(cmd,LOGGER);
                LOGGER.info("Exporting SBOM to: {}", generatedSbom.toPath());
                System.out.println("Exporting SBOM to: " + generatedSbom.toPath());
            } catch (IOException e) {
                LOGGER.error("Failed to run Trivy for SBOM generation");
                LOGGER.error(e.toString());
                e.printStackTrace();
            }
        }
        // TODO: figure out how to allow user to specify images right now this is just a placeholder
        else if (genTool.contains("image")) {
            String[] cmd = {"trivy",
                    "image", // arg to indicate image generation
                    "--format", spec,
                    "--output", generatedSbom.toPath().toAbsolutePath().toString(), // output path
                    projectLocation.toAbsolutePath().toString()}; // product under analysis path
            LOGGER.info(Arrays.toString(cmd));
            // runs the command built above and captures the output, trivy itself will handle the file saving
            try {
                helperFunctions.getOutputFromProgram(cmd,LOGGER);
                LOGGER.info("Exporting SBOM to: {}", generatedSbom.toPath());
                System.out.println("Exporting SBOM to: " + generatedSbom.toPath());
            } catch (IOException e) {
                LOGGER.error("Failed to run Trivy for SBOM generation");
                LOGGER.error(e.toString());
                e.printStackTrace();
            }
        }

    }


}
