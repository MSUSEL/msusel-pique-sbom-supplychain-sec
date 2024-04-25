package data.interfaces;

public interface JsonMarshaler<T> {
    T unmarshalJson(String json);
    String marshalJson(T obj);
}
