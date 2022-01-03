/*
 * Created by 郑明亮 on 2022年1月3日 23:01:45.
 */

//

package com.alianga.valid.validation;

import com.alianga.valid.annotation.ValueOfEnum;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
/**
 * @author  zhengmingliang
 * @email mpro@vip.qq.com
 * @since 2022/1/3 23:01
 * @version 1.0.0
 * @description 校验必须为指定枚举类中的一个值
 */
public class ValueOfEnumValidator implements ConstraintValidator<ValueOfEnum,Object> {

    private List<String> collect;

    @Override
    public void initialize(ValueOfEnum constraintAnnotation) {
        collect = Arrays.stream(constraintAnnotation.enumClass().getEnumConstants())
                .map(e -> e.name().toUpperCase()).collect(Collectors.toList());

    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        // 不允许为null
        if (value == null) {
            return false;
        }
        return collect.contains(value.toString().toUpperCase());
    }
}
