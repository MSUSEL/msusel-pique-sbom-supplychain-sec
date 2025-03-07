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

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import model.SbomQualityModelImport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.model.QualityModel;
import pique.model.QualityModelExport;
import pique.runnable.AQualityModelDeriver;
import pique.utility.PiqueProperties;
import presentation.PiqueData;
import presentation.PiqueDataFactory;
import tool.CveBinToolWrapper;
import tool.GrypeWrapper;
import tool.TrivyWrapper;

import utilities.helperFunctions;

/**
 * Utility driver class responsible for running the calibration module's procedure.
 * This uses a benchmark repository, quality model description, directory of comparison matrices, and
 * instances of language-specific analysis tools as input to perform a 3 step process of
 * (1) Derive thresholds
 * (2) Elicitate weights
 * (3) Apply these results to the quality model to generate a fully derived quality model
 */
public class QualityModelDeriver extends AQualityModelDeriver {
    private static final Logger LOGGER = LoggerFactory.getLogger(QualityModelDeriver.class);
    PiqueData piqueData = new PiqueDataFactory().getPiqueData();

    public QualityModelDeriver(String propertiesPath){
        init(propertiesPath);
    }

    public QualityModelDeriver(){
        init("");

    }

    private void init(String propertiesPath){
        LOGGER.info("Beginning deriver");

        Properties prop = null;
        try {
            prop = propertiesPath.isEmpty() ? PiqueProperties.getProperties() : PiqueProperties.getProperties(propertiesPath);
        } catch (IOException e) {
            e.printStackTrace();
        }

        Path blankqmFilePath = Paths.get(prop.getProperty("blankqm.filepath"));
        Path derivedModelFilePath = Paths.get(prop.getProperty("results.directory"));

        // Initialize objects
        String projectRootFlag = "";
        Path benchmarkRepo = Paths.get(prop.getProperty("benchmark.repo"));

        LOGGER.info("Initializing tools");
        ITool gyrpeWrapper = new GrypeWrapper(piqueData, propertiesPath);
        ITool trivyWrapper = new TrivyWrapper(piqueData, propertiesPath);
        //ITool cveBinToolWrapper = new CveBinToolWrapper(piqueData, propertiesPath);
        //Set<ITool> tools = Stream.of(gyrpeWrapper,trivyWrapper, cveBinToolWrapper).collect(Collectors.toSet());
        Set<ITool> tools = Stream.of(gyrpeWrapper,trivyWrapper).collect(Collectors.toSet());
        SbomQualityModelImport qmImport = new SbomQualityModelImport(blankqmFilePath);
        QualityModel qmDescription = qmImport.importQualityModel();
        //qmDescription = pique.utility.TreeTrimmingUtility.trimQualityModelTree(qmDescription);


        QualityModel derivedQualityModel = deriveModel(qmDescription, tools, benchmarkRepo, projectRootFlag);
        Path jsonOutput = new QualityModelExport(derivedQualityModel).exportToJson(derivedQualityModel.getName(), derivedModelFilePath);

        QualityModel trimmedDerivedQualityModel = helperFunctions.trimBenchmarkedMeasuresWithNoFindings(derivedQualityModel);
        Path trimmedJsonOutput = new QualityModelExport(trimmedDerivedQualityModel)
                .exportToJson(trimmedDerivedQualityModel
                        .getName() + "_trimmed", derivedModelFilePath);

        LOGGER.info("Quality Model derivation finished. You can find the file at " + jsonOutput.toAbsolutePath().toString());
        System.out.println("Quality Model derivation finished. You can find the file at " + jsonOutput.toAbsolutePath().toString());
    }

}
