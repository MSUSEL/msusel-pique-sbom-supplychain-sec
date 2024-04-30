package data.interfaces;

public interface IJsonMarshaler<T> {
    T unmarshalJson(String json);
    String marshalJson(T obj);
}
