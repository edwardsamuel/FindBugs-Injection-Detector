package id.ac.itb.injection.annotation;

import id.ac.itb.injection.Vulnerability;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *
 * @author Edward Samuel
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.PARAMETER)
public @interface SensitiveParameter {
    Vulnerability[] vulnerabilities();
}
