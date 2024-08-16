package web;

import exceptions.ElementNotFoundException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.io.IOException;


public class CweWebScraper {
    //    private WebDriver driver;
    private final String BASE_URL = "https://cwe.mitre.org/data/definitions/";
    private final String HTML = ".html";
    //
//    public CweWebScraper() {
//        WebDriverManager.firefoxdriver().setup();
//        this.driver = new FirefoxDriver();
//    }
//
//    public String getCweDescription(String cweId) {
//        String url = BASE_URL + formatCweId(cweId) + HTML;
//        driver.navigate().to(url);
//        WebElement cweStatus = driver.findElement(By.className("status"));
//        WebElement vulnMapping = cweStatus.findElement(By.className("tool"));
//        WebElement mappingStatusSpan = vulnMapping.findElement(By.tagName("span"));
//        String mappingStatus = mappingStatusSpan.getText();
//
//        return mappingStatus;
//    }
//
    public String getCweDescription(String cweId) {
        Document document = getWebPage(cweId);
        Element vulnMapping;
        Element mappingStatusSpan;
        String mappingStatus = "";

        Element cweStatus = document.getElementsByClass("status").first();
        try {
            checkElementNotNull(cweStatus);
            vulnMapping = cweStatus.getElementsByClass("tool").first();
            checkElementNotNull(vulnMapping);
            mappingStatusSpan = vulnMapping.getElementsByTag("span").first();
            checkElementNotNull(mappingStatusSpan);
            mappingStatus = mappingStatusSpan.text();
            System.out.println(mappingStatus);
        } catch (ElementNotFoundException e) {
            System.out.println("INFO: Element not found in document");
        }

        return mappingStatus;
    }

    private String formatURL(String cweId) {
        return BASE_URL + cweId.substring(4) + HTML;
    }

    private Document getWebPage(String cweId) {
        try {
            return Jsoup.connect(formatURL(cweId)).get();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void checkElementNotNull(Element element) throws ElementNotFoundException {
        if (element == null) {
            throw new ElementNotFoundException("element not found in Document");
        }
    }
}
