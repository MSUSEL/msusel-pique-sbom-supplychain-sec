package toolTests;

import org.junit.Test;
import web.CweDescriptionParser;

import java.util.Map;

import static org.junit.Assert.*;

public class CweDescriptionParserTest {
    CweDescriptionParser cweDescriptionParser = new CweDescriptionParser();

    @Test
    public void testBuildCweDescriptions() {
        Map<String, String> descriptions = cweDescriptionParser.buildCweDescriptionsMap("./src/main/resources/cwe_v4.15.xml");
    }

    @Test
    public void testDumpWeaknessToFile() {
        cweDescriptionParser.dumpWeaknessDescriptionsToFile("./src/main/resources/cwe_v4.15.xml");
    }
}
