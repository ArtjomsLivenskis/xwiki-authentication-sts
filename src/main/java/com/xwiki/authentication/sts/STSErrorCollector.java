package com.xwiki.authentication.sts;

import java.util.ArrayList;
import java.util.List;

/**
 * STSErrorCollector - Class - saves - Throwable objects in List. 
 * Have method to convert to string saved errors (listErrors()).
 * Have errorList, which is ArrayList<Throwable> in which are stored Errors.
 * You can easily add Throwable objects with void addError(Object obj). If will
 * be passed non-Throwable object to method - nothing will happen.
 * 
 * @version 1.0
 */
public class STSErrorCollector {

	/**
     * List of Throwable objects to store current errors
     */
	private List<Throwable> errorList;

	/**
     * Contructor - is making a 
     */
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
		String normalizedList = "";
		if (errorList.size() > 0) {
			normalizedList = "\n\n***** ERROR LIST *****\n";
			for (Throwable currentThrowable : errorList) {
				normalizedList = normalizedList + currentThrowable;
				if (currentThrowable.getCause() == null)
					normalizedList += "\n";
				else
					normalizedList = normalizedList
							+ currentThrowable.getCause()
							+ "\n";
			}
			normalizedList = normalizedList + "**********************"
					+ "\n";
		}
		return normalizedList;
	}

	/**
	 * <b>clearErrorList</b> - Clear List of errors
	 * @throws ConfigurationException - exception of open SAML's configuration
	 */
	public void clearErrorList() {
		errorList.clear();
	}
	
	/**
	 * <b>geterrorListLength</b> - get size of error list
	 * @return size_of_errors
	 */
	public int geterrorListLength() {
		return errorList.size();
	}
}
