package modelTests;

import org.junit.Test;
import pique.utility.PiqueProperties;
import runnable.QualityModelDeriver;
import runnable.SingleProjectEvaluator;

import java.io.IOException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.fail;

public class DeriveEvalTest {

    @Test
    public void EvalAndDeriveTest() throws IOException {
        Properties prop = PiqueProperties.getProperties("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/main/resources/pique-properties-temp.properties");

        String sbomInputPath = prop.getProperty("project.sbom-input");


        try {
            //QualityModelDeriver qm = new QualityModelDeriver("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/main/resources/pique-properties-temp.properties");
            SingleProjectEvaluator eval = new SingleProjectEvaluator(sbomInputPath, "", "", "/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/main/resources/pique-properties-temp.properties");
        }
        catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
            fail();
        }

    }

}
