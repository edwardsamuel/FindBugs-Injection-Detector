package id.ac.itb.cs.annotation;

import id.ac.itb.cs.CleanerType;
import id.ac.itb.cs.Vulnerability;

import javax.annotation.meta.TypeQualifier;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *
 * @author Edward Samuel
 */

@Retention(RetentionPolicy.CLASS)
@TypeQualifier
@Target(value = {ElementType.FIELD, ElementType.METHOD})
public @interface Cleaner {
    CleanerType type();
    Vulnerability[] vulnerabilities();
}
