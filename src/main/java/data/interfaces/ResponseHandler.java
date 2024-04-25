package data.interfaces;

import org.apache.http.HttpResponse;

import java.io.IOException;

public interface ResponseHandler {
    <T> T handleResponse(T pojoClass, HttpResponse httpResponse) throws IOException;
}
