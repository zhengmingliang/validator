/**
 * Created by 郑明亮 on 2022/1/3 22:59.
 */
package com.alianga.valid.annotation;

import com.alianga.valid.validation.ValueOfEnumValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * @author  zhengmingliang
 * @email mpro@vip.qq.com
 * @since 2022/1/3 22:59
 * @version 1.0.0
 * @description 是某个枚举类中的一个值
 */
@Target({ METHOD, FIELD})
@Retention(RUNTIME)
@Documented
@Constraint(validatedBy = ValueOfEnumValidator.class)
public @interface ValueOfEnum {
    Class<? extends Enum<?>> enumClass();
    String message() default "必须为指定的${\"\".equals(example) ? enumClass : example}中的一个";
    String example() default "";

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
