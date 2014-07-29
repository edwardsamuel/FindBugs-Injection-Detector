package id.ac.itb.cs.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *
 * @author Edward Samuel
 */
@Retention(RetentionPolicy.CLASS)
@Target(value = {ElementType.FIELD, ElementType.METHOD})
public @interface ReturnContaminated {

}
