package data.baseClasses;

import org.apache.http.NameValuePair;

import java.util.List;

/**
 * Base class for any HTTP Request objects
 */
public abstract class BaseRequest {
    protected String httpMethod;
    protected String baseURI;
    protected List<String> headers;
    protected List<NameValuePair> params;

    public BaseRequest(String httpMethod, String baseURI, List<String> headers) {
        this.httpMethod = httpMethod;
        this.baseURI = baseURI;
        this.headers = headers;
    }

    public abstract BaseResponse executeRequest();
}
