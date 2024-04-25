package data;

import data.baseClasses.BaseResponse;
import data.ghsaData.SecurityAdvisory;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GHSAResponse extends BaseResponse {
    private SecurityAdvisory securityAdvisory;
}
