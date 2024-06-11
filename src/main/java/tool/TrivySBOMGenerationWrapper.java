package tool;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utilities.helperFunctions;


public class TrivySBOMGenerationWrapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    public TrivySBOMGenerationWrapper() {

    }

    public void generate(Path projectLocation) {
        LOGGER.info("Trivy Generation --- Generating SBOM for {}", projectLocation.toString());

        File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-" + projectLocation.getFileName() + ".json");
        String spec = "cyclonedx"; // output format

        // command for running Trivy SBOM generation on the command line
        // trivy fs --format {spec} --output {output_name.json} {file_system}
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


}
