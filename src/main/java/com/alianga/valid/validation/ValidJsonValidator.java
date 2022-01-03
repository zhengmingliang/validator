package com.alianga.valid.validation;
/**
 * Created by 郑明亮 on 2022/1/3 22:37.
 */

import com.alianga.valid.annotation.ValidJson;
import com.alibaba.fastjson.JSONValidator;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

/**
 * @author 郑明亮
 * @version 1.0
 * @date 2022/1/3 22:37
 * @description 校验是否为json格式
 */
public class ValidJsonValidator implements ConstraintValidator<ValidJson,String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return JSONValidator.from(value).validate();
    }
}
