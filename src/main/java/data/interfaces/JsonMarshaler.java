package data.interfaces;

import org.json.JSONObject;

public interface JsonMarshaler<T> {
    T unmarhsalJson(String json);
    String marshalJson(T obj);
}
