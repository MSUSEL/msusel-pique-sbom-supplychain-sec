package data.ghsaData;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SecurityAdvisory {
    private String ghsaId;
    private String summary;
    private Cwes cwes;
}
