package data;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NvdMirrorMetadata {
    private String id;
    private String totalResults;
    private String format;
    private String version;
    private String timestamp;
}
