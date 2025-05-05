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
package runnable;

import net.sourceforge.argparse4j.inf.ArgumentParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * Main entry point for the PIQUE-SBOM-SUPPLYCHAIN-SEC application. This class handles the
 * initial command-line interface setup for the application, processing input arguments to
 * determine the operational mode (either deriving a new quality model or evaluating SBOMs),
 * and initiating the appropriate processes based on the user's choice.
 *
 * @author Eric O'Donoghue
 */
public class Wrapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(Wrapper.class);

    public static void main(String[] args) throws ArgumentParserException, IOException {
        Namespace namespace = null;
        // setup command line argument parsing
        boolean helpFlag = check_help(args);
        ArgumentParser parser = ArgumentParsers.newFor("Wrapper").build()
                .defaultHelp(true)
                .defaultHelp(true)
                .description("Entry point for PIQUE-SBOM-SUPPLYCHAIN-SEC");
        parser.addArgument("--runType")
                .setDefault("derive")
                .choices("derive", "evaluate")
                .help("derive: derives a new quality model from the benchmark repository" +
                        "\nevaluate: evaluates SBOMs located in input/projects with derived quality model");
        parser.addArgument("--version")
                .action(Arguments.storeTrue())
                .setDefault(false)
                .help("print version information and terminate program");
        parser.addArgument("--gen_tool")
                .setDefault("none")
                .choices("syft", "trivy", "none")
                .help("specify the tool to use for SBOM generation");
        parser.addArgument("--properties")
                .setDefault("")
                .help("specify the properties file to use for configuration");
        parser.addArgument("--derived_model")
                .setDefault("npm-trimmed")
                .help("specify the derived model to use for evaluation");

        if (helpFlag) {
            System.out.println(parser.formatHelp());
            return;
        } else {
            namespace = parser.parseArgs(args);
        }


        String runType = namespace.getString("runType");
        String genTool = namespace.getString("gen_tool");
        boolean printVersion = namespace.getBoolean("version");

        if (printVersion) {
            String version = "2.0"; // TODO FIX TO BE DYNAMIC
            System.out.println("PIQUE-SBOM-SUPPLYCHAIN-SEC version " + version);
            return;
        }

        Properties prop;
        String propertiesPath = namespace.getString("properties");
        String derivedModel = namespace.getString("derived_model");
        if (propertiesPath.isEmpty()) {
            switch (derivedModel) {
                case "npm":
                    propertiesPath = "src/main/resources/properties-npm.properties";
                    break;
                case "npm-trimmed":
                    propertiesPath = "src/main/resources/properties-npm-trimmed.properties";
                    break;
                case "docker":
                    propertiesPath = "src/main/resources/properties-docker.properties";
                    break;
                case "docker-trimmed":
                    propertiesPath = "src/main/resources/properties-docker-trimmed.properties";
                    break;
                default:
                    LOGGER.error("Illegal Argument Exception: incorrect input parameter given. Use --help for more information.");
                    System.out.println("Incorrect input parameters given. Use --help for more information");
                    throw new IllegalArgumentException("Incorrect input parameters given. Use --help for more information");
            }
        }
        prop = PiqueProperties.getProperties(propertiesPath);

        if ("derive".equals(runType)) {
            // kick off deriver
            new QualityModelDeriver(propertiesPath);
        }
        else if ("evaluate".equals(runType)) {
            // kick off evaluator
            // get path to input projects
            String sbomInputPath = prop.getProperty("project.sbom-input");
            new SingleProjectEvaluator(sbomInputPath, genTool, "", propertiesPath);
        }
        else {
            LOGGER.error("Illegal Argument Exception: incorrect input parameter given. Use --help for more information.");
            System.out.println("Incorrect input parameters given. Use --help for more information");
            throw new IllegalArgumentException("Incorrect input parameters given. Use --help for more information");
        }
    }

    private static boolean check_help(String[] args) {
        // check if the help flag was used
        for (String arg : args) {
            if (arg.equals("--help")) {
                return true;
            }
        }
        return false;
    }

}
