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
public class TrivySbomGenerationWrapper implements IGenerationTool {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    /**
     * Initializes a new instance of the TrivySBOMGenerationWrapper class.
     */
    public TrivySbomGenerationWrapper() {

    }

    /**
     * Generates an SBOM for a given project location using Trivy. The SBOM is created in the CycloneDX format
     * and saved to a predetermined directory under the project's root directory.
     * This method constructs the command to run Trivy with the necessary arguments to produce the SBOM,
     * executes the command, and logs the process and potential errors.
     *
     * @param projectLocation The file path of the project directory for which to generate the SBOM.
     */
    public void generateSource(Path projectLocation) {
        LOGGER.info("Trivy Generation --- Generating SBOM for source code: {}", projectLocation.toString());
        File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-trivy-cdx-" + projectLocation.getFileName() + ".json");
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

    public void generateImage(Path projectLocation) {
        LOGGER.info("Trivy Generation --- Generating SBOM for image: {}", projectLocation.toString());
        File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-trivy-cdx-" + projectLocation.getFileName() + ".json");
        String spec = "cyclonedx"; // output format

        // open the txt file given with projectLocation and extract the image name:version as a string
        String imageName = helperFunctions.getImageName(projectLocation);

        if (imageName.isEmpty()) {
            System.out.println("Failed to read image name from file: " + projectLocation);
            System.out.println("Expected input format: text file containing a single docker image in the format name:tag");
            System.out.println("Skipping generation");
            LOGGER.error("Failed to read image name from file: {}", projectLocation);
            LOGGER.error("Expected input format: text file containing a single docker image in the format name:tag");
            LOGGER.error("Skipping generation");
            return;
        }

        String[] cmd = {"trivy",
                "image", // arg to indicate image generation
                "--format", spec,
                "--output", generatedSbom.toPath().toAbsolutePath().toString(), // output path
                imageName}; // product under analysis path
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
