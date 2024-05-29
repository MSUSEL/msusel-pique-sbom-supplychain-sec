package data.baseClasses;

import lombok.Getter;
import lombok.Setter;

/**
 * Base class for any HTTP Response Objects
 */
@Getter
@Setter
public abstract class BaseResponse {
    protected int status;
    protected String contentType;
    protected int contentLength;
    protected String auth;
    protected String date;
}
