/**
 * Created by 郑明亮 on 2022/1/3 22:59.
 */
package com.alianga.valid.annotation;

import javax.validation.Payload;

/**
 * @author  zhengmingliang
 * @email mpro@vip.qq.com
 * @since 2022/1/3 22:59
 * @version 1.0.0
 * @description 是某个枚举类中的一个值
 */
public @interface ValueOfEnum {
    Class<? extends Enum<?>> enumClass();
    String message() default "必须为指定的${\"\".equals(example) ? enumClass : example}中的一个";
    String example() default "";

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
