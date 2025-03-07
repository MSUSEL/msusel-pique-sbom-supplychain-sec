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

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import evaluator.SbomProject;
import lombok.Getter;
import lombok.Setter;
import model.SbomQualityModelImport;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.model.*;
import pique.runnable.ASingleProjectEvaluator;
import pique.utility.PiqueProperties;
import presentation.PiqueData;
import presentation.PiqueDataFactory;
import tool.*;

/**
 * Behavioral class responsible for running TQI evaluation of a single project
 */
// TODO (1.0): turn into static methods (maybe unless logger problems)
public class SingleProjectEvaluator extends ASingleProjectEvaluator {
    private final PiqueData piqueData = new PiqueDataFactory().getPiqueData();
    private static final Logger LOGGER = LoggerFactory.getLogger(SingleProjectEvaluator.class);

//    //default properties location
//    @Getter @Setter
//    private String propertiesLocation = "src/main/resources/pique-properties.properties";

    public SingleProjectEvaluator(String sbomDirectory, String genTool, String parameters) {
        init(sbomDirectory, genTool, parameters, null);
    }

    public SingleProjectEvaluator(String sbomDirectory, String genTool, String parameters, String propertiesPath) {
        init(sbomDirectory, genTool, parameters, propertiesPath);
    }

    /**
     * Initializes the evaluation process for a single project by setting up the necessary paths and properties,
     * generating Software Bill of Materials (SBOM) for each project found in the source code directory using Trivy,
     * and preparing the analysis tools. This method first checks for source code files, generates SBOMs for them,
     * and then proceeds to evaluate these SBOMs using a set of predefined tools (GrypeWrapper, TrivyWrapper, etc.).
     * Results of the evaluations are saved in a specified results directory. This method effectively serves as
     * a setup and execution pipeline for SBOM generation and subsequent vulnerability analysis within the PIQUE framework.
     *
     * @param sbomDirectory The directory where the generated SBOMs are stored.
     */
    public void init(String sbomDirectory, String genTool, String parameters, String propertiesPath) {
        LOGGER.info("Starting Analysis");
        Properties prop = null;
        try {
            prop = propertiesPath == null || propertiesPath.isEmpty() ? PiqueProperties.getProperties() : PiqueProperties.getProperties(propertiesPath);
        } catch (IOException e) {
            e.printStackTrace();
        }


        Path sbomPath = Paths.get(sbomDirectory);

        String sourceCodeInputPath = prop.getProperty("project.source-code-input");
        String imageInputPath = prop.getProperty("project.image-input");
        Path sourceCodePath = Paths.get(sourceCodeInputPath);
        Path imagesPath = Paths.get(imageInputPath);
        Path resultsDir = Paths.get(prop.getProperty("results.directory"));

        /**
         * Code that checks if source code is present to generate SBOMs for, we iterate through each directory or
         * file in the source code directory. We generate SBOMs (currently using specificed gen tool) for each project in the
         * source code directory. The resulting SBOMs are placed in the input/projects/SBOM directory. The code
         * then proceeds to evaluate each SBOM in the input/projects/SBOM directory.
         */
        LOGGER.info("Generating SBOMs for source code and images");
        Set<Path> sourceCodeRoots = new HashSet<>();
        File[] sourceCodeToGenerateSbomsFrom = sourceCodePath.toFile().listFiles();
        if (sourceCodeToGenerateSbomsFrom != null) {
            for (File f : sourceCodeToGenerateSbomsFrom) {
                if (!f.getName().equals(".gitignore")) { // Check to avoid adding .gitignore
                    sourceCodeRoots.add(f.toPath()); // Add both files and directories except .gitignore
                }
            }
        }

        Set<Path> imageRoots = new HashSet<>();
        File[] imagesToGenerateSbomsFrom = imagesPath.toFile().listFiles();
        if (imagesToGenerateSbomsFrom != null) {
            for (File f : imagesToGenerateSbomsFrom) {
                if (!f.getName().equals(".gitignore")) { // Check to avoid adding .gitignore
                    imageRoots.add(f.toPath()); // Add both files and directories except .gitignore
                }
            }
        }

        IGenerationTool sbomGenerator;
        if (genTool.contains("syft")) {
            sbomGenerator = new SyftSbomGenerationWrapper();
        }
        else if (genTool.contains("trivy")) {
            sbomGenerator = new TrivySbomGenerationWrapper();
        }
        else {
            sbomGenerator = null;
        }

        // Generate SBOMs for each project in the source code directory, if one wasn't specified skip generation
        if (sbomGenerator != null) {
            for (Path projectToGenerateSbomFor : sourceCodeRoots){
                LOGGER.info("Generating SBOM for: {}\nwith generation tool: {}", projectToGenerateSbomFor.toString(), genTool);
                System.out.println("Generating SBOM for: " + projectToGenerateSbomFor + "\nwith generation tool: " + genTool);
                sbomGenerator.generateSource(projectToGenerateSbomFor);
            }
            for (Path projectToGenerateSbomFor : imageRoots){
                LOGGER.info("Generating SBOM for: {}\nwith generation tool: {}", projectToGenerateSbomFor.toString(), genTool);
                System.out.println("Generating SBOM for: " + projectToGenerateSbomFor + "\nwith generation tool: " + genTool);
                sbomGenerator.generateImage(projectToGenerateSbomFor);
            }
        }
        else {
            System.out.println("No SBOM generation tool specified. Skipping generation of SBOMs.");
            LOGGER.warn("No SBOM generation tool specified. Skipping generation of SBOMs.");
        }


        // now that SBOMs have been generated from any present source code we proceed as a normal pique run

        // get derived quality model location
        Path qmLocation = Paths.get(prop.getProperty("derived.qm"));

        // initialize SBOM analysis tools that will run on each SBOM in the input/projects/SBOM directory
        LOGGER.info("Initializing SBOM analysis tools");
        ITool gyrpeWrapper = new GrypeWrapper(piqueData, propertiesPath);
        ITool trivyWrapper = new TrivyWrapper(piqueData, propertiesPath);
        ITool cveBinToolWrapper = new CveBinToolWrapper(piqueData, propertiesPath);
        //Set<ITool> tools = Stream.of(gyrpeWrapper,trivyWrapper, cveBinToolWrapper).collect(Collectors.toSet());
        Set<ITool> tools = Stream.of(gyrpeWrapper,trivyWrapper).collect(Collectors.toSet());

        // loop through each SBOM in the input/projects/SBOM directory and store paths in a list
        LOGGER.info("Evaluating SBOMs");
        Set<Path> sbomRoots = new HashSet<>();
        File[] sbomsToAssess = sbomPath.toFile().listFiles();
        assert sbomsToAssess != null;
        for (File f : sbomsToAssess){
            if (f.isFile() && !f.getName().equals(".gitignore")){
                sbomRoots.add(f.toPath());
            }
        }

        // PIQUE evaluator entry point - evaluates each SBOM in the input/projects/SBOM directory and stores results in out directory
        for (Path projectUnderAnalysisPath : sbomRoots){
            LOGGER.info("Project to analyze: {}", projectUnderAnalysisPath.toString());
            Path outputPath = runEvaluator(projectUnderAnalysisPath, resultsDir, qmLocation, tools);
            LOGGER.info("output: {}", outputPath.getFileName());
            System.out.println("output: " + outputPath.getFileName());
            System.out.println("exporting compact: " + project.exportToJson(resultsDir, true));

            // TODO: Remove later (only here for experimenting with the pdf utility function)
            Pair<String, String> name = Pair.of("projectName", project.getName());
            String fileName = project.getName() + "_TRIMMED-TESTING_compact_evalResults" + parameters;
            QualityModelExport qmExport = new QualityModelCompactExport(project.getQualityModel(), name);
            qmExport.exportToJson(fileName, resultsDir);
        }
    }

    @Override
    public Path runEvaluator(Path projectDir, Path resultsDir, Path qmLocation, Set<ITool> tools) {
        // Initialize data structures
        initialize(projectDir, resultsDir, qmLocation);
        SbomQualityModelImport qmImport = new SbomQualityModelImport(qmLocation);
        QualityModel qualityModel = qmImport.importQualityModel();
        project = new SbomProject(FilenameUtils.getBaseName(projectDir.getFileName().toString()), projectDir, qualityModel);

        // Validate State
        validatePreEvaluationState(project);

        // Run the static analysis tools process
        Map<String, Diagnostic> allDiagnostics = new HashMap<>();
        tools.forEach(tool -> {
            allDiagnostics.putAll(runTool(projectDir, tool));
        });

        // Apply tool results to Project object
        project.updateDiagnosticsWithFindings(allDiagnostics);

        BigDecimal tqiValue = project.evaluateTqi();
        LOGGER.info("TQI value: {}", tqiValue);
        System.out.println("TQI value: " + tqiValue);

        // Create a file of the results and return its path
        return project.exportToJson(resultsDir);
    }
}
