/*
 * Created by 郑明亮 on 2020/11/26 19:25.
 */

//

package com.alianga.valid.validation;

import com.alianga.valid.annotation.ListNotHasNull;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.List;
/**
 * @author  zhengmingliang
 * @email mpro@vip.qq.com
 * @since 2022/1/3 22:53
 * @version 1.0.0
 * @description 校验List集合中不能包含null元素
 */
public class ListNotHasNullValidatorImpl implements ConstraintValidator<ListNotHasNull, List> {

    private int value;

    @Override
    public void initialize(ListNotHasNull constraintAnnotation) {
        //传入value 值，可以在校验中使用
        this.value = constraintAnnotation.value();
    }

    @Override
    public boolean isValid(List list, ConstraintValidatorContext constraintValidatorContext) {
        if(list == null || list.isEmpty()){
            return false;
        }
        for (Object object : list) {
            if (object == null) {
                //如果List集合中含有Null元素，校验失败
                return false;
            }
        }
        return true;
    }
}