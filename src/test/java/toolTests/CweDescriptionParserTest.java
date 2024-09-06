package toolTests;

import org.junit.Test;
import web.CweDescriptionParser;

import java.util.Map;

import static org.junit.Assert.*;

public class CweDescriptionParserTest {
    CweDescriptionParser cweDescriptionParser = new CweDescriptionParser();

    @Test
    public void testBuildCweDescriptions() {
        Map<String, String> descriptions = cweDescriptionParser.buildCweDescriptionsMap("./src/main/resources/cwec_v4.15.xml");
    }

    @Test
    public void testDumpWeaknessToFile() {
        cweDescriptionParser.dumpWeaknessDescriptionsToFile("./src/main/resources/cwec_v4.15.xml");
    }

    @Test
    public void testBuildWeaknessDescriptionMapFromFile() {
        Map<String, String> descriptions = cweDescriptionParser.buildWeaknessDescriptionMapFromFile("./out/CweDescriptions.json");
        String result1 = descriptions.get("1004");
        String result2 = descriptions.get("CWE-1004");

        assertNull(result1);
        assertNotNull(result2);
    }
}
