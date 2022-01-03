package com.alianga.valid.annotation;

import com.alianga.valid.validation.ValidJsonValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Created by 郑明亮 on 2022/1/3 22:32.
 */
@Target({ METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER })
@Retention(RUNTIME)
@Documented
@Constraint(validatedBy = ValidJsonValidator.class)
public @interface ValidJson {
    /**
     * 错误提示信息
     */
    String message() default "Json格式错误";

    Class<?>[] groups() default { };

    Class<? extends Payload>[] payload() default { };
}
