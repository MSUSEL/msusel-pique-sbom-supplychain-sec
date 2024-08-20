package toolTests;

import org.junit.Test;
import web.CweWebScraper;
import web.CweDescriptionParser;

import java.util.Map;

import static org.junit.Assert.assertEquals;

public class WebScraperTest {
    CweWebScraper cweWebScraper = new CweWebScraper();
    CweDescriptionParser cweDescriptionParser = new CweDescriptionParser();

    @Test
    public void testGetCweDescription() {
        String result = cweWebScraper.getCweStatus("CWE-502");
        assertEquals("ALLOWED", result);
    }

    @Test
    public void testBuildCweDescriptions() {
        Map<String, String> descriptions = cweDescriptionParser.buildCweDescriptionsMap("./src/main/resources/cwe_v4.15.xml");
    }

    @Test
    public void testDumpWeaknessToFile() {
        cweDescriptionParser.dumpWeaknessDescriptionsToFile("./src/main/resources/cwe_v4.15.xml");
    }
}
