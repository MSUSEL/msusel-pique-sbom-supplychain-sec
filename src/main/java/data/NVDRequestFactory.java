package data;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import java.util.ArrayList;
import java.util.List;

public class NVDRequestFactory {

    // Constructors
    public NVDRequest createNVDRequest(String httpMethod, String baseURI, List<String> headers, int startIndex, int resultsPerPage) {
        return new NVDRequest(httpMethod, baseURI, headers, configureBasicParams(startIndex, resultsPerPage));
    }

    public NVDRequest createNVDRequest(String httpMethod, String baseURI, List<String> headers, int startIndex, int resultsPerPage, String lastModStartDate, String lastModEndDate) {
        return new NVDRequest(httpMethod, baseURI, headers, configureUpdateParams(startIndex, resultsPerPage, lastModStartDate, lastModEndDate));
    }

    // helper methods
    private List<NameValuePair> configureBasicParams(int startIndex, int resultsPerPage) {
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("startIndex", Integer.toString(startIndex)));
        params.add(new BasicNameValuePair("resultsPerPage", Integer.toString(resultsPerPage)));

        return params;
    }

    private List<NameValuePair> configureUpdateParams(int startIndex, int resultsPerPage, String lastModStartDate, String lastModEndDate) {
        List<NameValuePair> params = configureBasicParams(startIndex, resultsPerPage);
        params.add(new BasicNameValuePair("lastModStartDate", lastModStartDate));
        params.add(new BasicNameValuePair("lastModEndDate", lastModEndDate));

        return params;
    }
}
