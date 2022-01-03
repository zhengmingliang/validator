/**
 * Created by 郑明亮 on 2022/1/3 23:30.
 */
package com.alianga.valid.validator;

/**
 * <p> this is your description</p>
 *
 * @author 郑明亮
 * @version 1.0.0
 * @time 2022/1/3 23:30
 */

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <p>
 * 为单个正则表达式或一组（数组）正则表达式构造验证器。
 * 默认情况下，验证是 <i>区分大小写<i>，但提供了构造函数以允许 <i>区分大小写<i>
 *     验证。例如，创建一个验证器，它对一组正则表达式执行 <i>case in-sensitive<i> 验证:
 * </p>
 * <pre>
 * <code>
 * String[] regexs = new String[] {...};
 * RegexValidator validator = new RegexValidator(regexs, false);
 * </code>
 * </pre>
 *
 * <ul>
 *   <li>Validate <code>true</code> or <code>false</code>:</li>
 *   <li>
 *     <ul>
 *       <li><code>boolean valid = validator.isValid(value);</code></li>
 *     </ul>
 *   </li>
 *   <li>Validate returning an aggregated String of the matched groups:</li>
 *   <li>
 *     <ul>
 *       <li><code>String result = validator.validate(value);</code></li>
 *     </ul>
 *   </li>
 *   <li>Validate returning the matched groups:</li>
 *   <li>
 *     <ul>
 *       <li><code>String[] result = validator.match(value);</code></li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * @since 1.0.0
 */
public class RegexValidator implements Serializable {

    private static final long serialVersionUID = -8832409930574867162L;

    private final Pattern[] patterns;

    /**
     * 正则表达式验证器(默认区分大小写)
     * @param regex 此验证器将验证的正则表达式
     */
    public RegexValidator(String regex) {
        this(regex, true);
    }

    /**
     * 正则表达式验证器
     *
     * @param regex         正则表达式
     * @param caseSensitive  <code>true</code> <i>区分大小写</i>, <code>false<code/> <i>不区分大小写</i>
     */
    public RegexValidator(String regex, boolean caseSensitive) {
        this(new String[] {regex}, caseSensitive);
    }

    /**
     * 正则表达式验证器（区分大小写） 匹配任何一组正则表达式的验证器。
     *
     * @param regexs 正则表达式集合
     */
    public RegexValidator(String[] regexs) {
        this(regexs, true);
    }


    /**
     * 正则表达式验证器
     *
     * @param regexs        正则表达式
     * @param caseSensitive 区分大小写
     */
    public RegexValidator(String[] regexs, boolean caseSensitive) {
        if (regexs == null || regexs.length == 0) {
            throw new IllegalArgumentException("Regular expressions are missing");
        }
        patterns = new Pattern[regexs.length];
        int flags =  (caseSensitive ? 0: Pattern.CASE_INSENSITIVE);
        for (int i = 0; i < regexs.length; i++) {
            if (regexs[i] == null || regexs[i].length() == 0) {
                throw new IllegalArgumentException("Regular expression[" + i + "] is missing");
            }
            patterns[i] =  Pattern.compile(regexs[i], flags);
        }
    }

    /**
     * 根据正则表达式集验证值.
     *
     * @param value 要验证的值.
     * @return  如果校验通过则返回<code>true</code>，否则返回 <code>false</code>.
     */
    public boolean isValid(String value) {
        if (value == null) {
            return false;
        }
        for (int i = 0; i < patterns.length; i++) {
            if (patterns[i].matcher(value).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * 根据返回匹配组数组的正则表达式集验证值。
     *
     * @param value 要验证的值.
     * @return 返回匹配到的字符串数组，如果匹配不到，则返回 <code>null<code>
     */
    public String[] match(String value) {
        if (value == null) {
            return null;
        }
        for (int i = 0; i < patterns.length; i++) {
            Matcher matcher = patterns[i].matcher(value);
            if (matcher.matches()) {
                int count = matcher.groupCount();
                String[] groups = new String[count];
                for (int j = 0; j < count; j++) {
                    groups[j] = matcher.group(j+1);
                }
                return groups;
            }
        }
        return null;
    }


    /**
     * 验证
     * 根据返回聚合组的字符串值的正则表达式集验证值。
     * @param value 要验证的值.
     * @return 由匹配的 <i>groups<i> 组成的聚合字符串值（如果有效）或 <code>null<code>（如果无效）
     */
    public String validate(String value) {
        if (value == null) {
            return null;
        }
        for (int i = 0; i < patterns.length; i++) {
            Matcher matcher = patterns[i].matcher(value);
            if (matcher.matches()) {
                int count = matcher.groupCount();
                if (count == 1) {
                    return matcher.group(1);
                }
                StringBuilder buffer = new StringBuilder();
                for (int j = 0; j < count; j++) {
                    String component = matcher.group(j+1);
                    if (component != null) {
                        buffer.append(component);
                    }
                }
                return buffer.toString();
            }
        }
        return null;
    }


    @Override
    public String toString() {
        StringBuilder buffer = new StringBuilder();
        buffer.append("RegexValidator{");
        for (int i = 0; i < patterns.length; i++) {
            if (i > 0) {
                buffer.append(",");
            }
            buffer.append(patterns[i].pattern());
        }
        buffer.append("}");
        return buffer.toString();
    }

}
