package toolTests;

import org.junit.Test;
import web.CweWebScraper;

import static org.junit.Assert.assertEquals;

public class WebScraperTest {
    CweWebScraper cweWebScraper = new CweWebScraper();

    @Test
    public void testGetCweDescription() {
        String result = cweWebScraper.getCweDescription("CWE-502");
        assertEquals("ALLOWED", result);
    }
}
