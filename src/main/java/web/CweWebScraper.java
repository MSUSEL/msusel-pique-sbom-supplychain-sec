package web;

import exceptions.ElementNotFoundException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class CweWebScraper {
    private static final Logger LOGGER = LoggerFactory.getLogger(CweWebScraper.class);

    public String getCweStatus(String cweId) {
        Document document = getWebPage(cweId);
        Element vulnMapping;
        Element mappingStatusSpan;
        String mappingStatus = "";

        Element cweStatus = document.getElementsByClass("status").first();
        try {
            vulnMapping = checkElementNotNull(cweStatus).getElementsByClass("tool").first();
            mappingStatusSpan = checkElementNotNull(vulnMapping).getElementsByTag("span").first();
            mappingStatus = checkElementNotNull(mappingStatusSpan).child(0).text();
        } catch (ElementNotFoundException e) {
            LOGGER.info("Element not found in document");
        }

        return mappingStatus;
    }

    private String formatURL(String cweId) {
        String BASE_URL = "https://cwe.mitre.org/data/definitions/";
        String HTML = ".html";

        return BASE_URL + cweId.substring(4) + HTML;
    }

    private Document getWebPage(String cweId) {
        try {
            return Jsoup.connect(formatURL(cweId)).get();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Element checkElementNotNull(Element element) throws ElementNotFoundException {
        if (element == null) {
            throw new ElementNotFoundException("element not found in Document");
        } else {
            return element;
        }
    }
}
