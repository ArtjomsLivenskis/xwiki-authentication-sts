package com.xwiki.authentication.sts;

import java.util.ArrayList;
import java.util.List;

import org.apache.tools.ant.types.resources.selectors.InstanceOf;
import org.opensaml.xml.ConfigurationException;

/**
 * STSErrorCollector - Class - saves - Throwable objects in List. 
 * And have method to list saved errors.
 * 
 * @version 1.0
 */
public class STSErrorCollector {

	private List<Throwable> errorList;

	public STSErrorCollector() {
		errorList = new ArrayList<Throwable>();
	}

	/**
	 * <b>STSErrorCollector</b> - adds Throwable object to errorsList
	 * if obj parameter is instanceof Throwable - then add it to List
	 *
	 * @param obj Object - if Throwable - then - adding to List<Throwable>
	 */
	public void addError(Object obj) {
		if (obj instanceof Throwable)
			errorList.add((Throwable) obj);
	}

	/**
	 * <b>listErrors</b> - Returns list of errors in String format 
	 * @return String error list line separated in a manual string format
	 */
	public String listErrors() {
		String normalizedList = System.lineSeparator() + "================"
				+ System.lineSeparator() + "ERROR LIST"
				+ System.lineSeparator() + "================"
				+ System.lineSeparator();
		for (Throwable currentThrowable : errorList) {
			normalizedList = normalizedList + currentThrowable + ": "
					+ currentThrowable.getCause() + System.lineSeparator();
		}
		return normalizedList + "================" + System.lineSeparator();
	}
	
	/**
	 * <b>clearErrorList</b> - Clear List of errors
	 * @throws ConfigurationException - exception of open SAML's configuration
	 */
	public void clearErrorList(){
		errorList.clear();
	}
}