package com.venafi.vcert.sdk.features;

import com.venafi.vcert.sdk.certificate.EllipticCurve;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class SupportedECCKeys {
	
	public static final SupportedECCKeys TPP = new SupportedECCKeys(List.of(EllipticCurve.EllipticCurveP256, EllipticCurve.EllipticCurveP384, EllipticCurve.EllipticCurveP521));
	
	private Map<String, EllipticCurve> ellipticCurveMap;
	
	public SupportedECCKeys(List<EllipticCurve> ellipticCurves) {
		ellipticCurveMap = ellipticCurves.stream().collect(Collectors.toMap(EllipticCurve::value, Function.identity()));
	}

	public boolean containsEllipticCurves(String[] curves){

		for (String curve : curves) {
			if(!containsEllipticCurve(curve))
				return false;
		}

		return true;
	}

	public boolean containsEllipticCurve(String value){
		return ellipticCurveMap.containsKey(value);
	}

	public EllipticCurve getEllipticCurve(String value){
		return ellipticCurveMap.get(value);
	}
}
