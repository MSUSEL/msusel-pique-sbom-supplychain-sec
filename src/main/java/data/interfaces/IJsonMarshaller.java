package data.interfaces;

public interface IJsonMarshaller<T> {
    T unmarshallJson(String json);
    String marshallJson(T obj);
}
