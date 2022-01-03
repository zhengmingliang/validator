package com.alianga.valid.validator;
/**
 * Created by 郑明亮 on 2022/1/3 23:19.
 */

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author 郑明亮
 * @version 1.0.0
 * @time 2022/1/3 23:19
 * @description
 */
public class EmailValidator implements Serializable {
    private static final String SPECIAL_CHARS = "\\p{Cntrl}\\(\\)<>@,;:'\\\\\\\"\\.\\[\\]";
    private static final String VALID_CHARS = "(\\\\.)|[^\\s" + SPECIAL_CHARS + "]";
    private static final String QUOTED_USER = "(\"(\\\\\"|[^\"])*\")";
    private static final String WORD = "((" + VALID_CHARS + "|')+|" + QUOTED_USER + ")";

    private static final String EMAIL_REGEX = "^(.+)@(\\S+)$";
    private static final String IP_DOMAIN_REGEX = "^\\[(.*)\\]$";
    private static final String USER_REGEX = "^" + WORD + "(\\." + WORD + ")*$";

    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);
    private static final Pattern IP_DOMAIN_PATTERN = Pattern.compile(IP_DOMAIN_REGEX);
    private static final Pattern USER_PATTERN = Pattern.compile(USER_REGEX);

    private static final int MAX_USERNAME_LEN = 64;

    private final boolean allowTld;

    /**
     *此类的单例实例，它不认为本地地址有效。
     */
    private static final EmailValidator EMAIL_VALIDATOR = new EmailValidator(false, false);

    /**
     * 此类的单例实例，它不认为本地地址有效。
     */
    private static final EmailValidator EMAIL_VALIDATOR_WITH_TLD = new EmailValidator(false, true);

    /**
     * 此类的单例实例，它认为本地地址有效。
     */
    private static final EmailValidator EMAIL_VALIDATOR_WITH_LOCAL = new EmailValidator(true, false);


    /**
     * 此类的单例实例，它认为本地地址有效。
     */
    private static final EmailValidator EMAIL_VALIDATOR_WITH_LOCAL_WITH_TLD = new EmailValidator(true, true);

    private final DomainValidator domainValidator;

    /**
     * 返回此验证器的 Singleton 实例。
     */
    public static EmailValidator getInstance() {
        return EMAIL_VALIDATOR;
    }

    /**
     * 返回此验证器的 Singleton 实例，并根据需要进行本地验证。
     *
     * @param allowLocal 认为本地地址是否有效
     * @param allowTld  是否允许TLD
     * @return 此验证器的单例实例
     */
    public static EmailValidator getInstance(boolean allowLocal, boolean allowTld) {
        if(allowLocal) {
            if (allowTld) {
                return EMAIL_VALIDATOR_WITH_LOCAL_WITH_TLD;
            } else {
                return EMAIL_VALIDATOR_WITH_LOCAL;
            }
        } else {
            if (allowTld) {
                return EMAIL_VALIDATOR_WITH_TLD;
            } else {
                return EMAIL_VALIDATOR;
            }
        }
    }

    /**
     * 注意：这个数组必须排序，否则不能使用二分搜索可靠地搜索它
     *
     * @param allowLocal 本地地址是否应被视为有效
     * @return 此验证器的单例实例
     */
    public static EmailValidator getInstance(boolean allowLocal) {
        return getInstance(allowLocal, false);
    }

    /**
     * 用于创建具有指定域验证器的实例的构造函数
     *
     * @param allowLocal 本地地址是否应被视为有效
     * @param allowTld 是否应该允许 TLD
     * @param domainValidator 允许覆盖 DomainValidator.
     * 实例必须具有相同的 allowLocal 设置.
     * @since 1.0.0
     */
    public EmailValidator(boolean allowLocal, boolean allowTld, DomainValidator domainValidator) {
        super();
        this.allowTld = allowTld;
        if (domainValidator == null) {
            throw new IllegalArgumentException("DomainValidator cannot be null");
        } else {
            if (domainValidator.isAllowLocal() != allowLocal) {
                throw new IllegalArgumentException("DomainValidator must agree with allowLocal setting");
            }
            this.domainValidator = domainValidator;
        }
    }

    /**
     * Protected constructor for subclasses to use.
     *
     * @param allowLocal Should local addresses be considered valid?
     * @param allowTld Should TLDs be allowed?
     */
    protected EmailValidator(boolean allowLocal, boolean allowTld) {
        this.allowTld = allowTld;
        this.domainValidator = DomainValidator.getInstance(allowLocal);
    }

    /**
     * 受保护的构造函数供子类使用。
     *
     * @param allowLocal 本地地址是否应被视为有效
     */
    protected EmailValidator(boolean allowLocal) {
        this(allowLocal, false);
    }

    /**
     * <p>检查字段是否具有有效的电子邮件地址.</p>
     *
     * @param email 要验证的邮件地址。 <code>null<code> 值被视为无效。
     * @return 如果电子邮件地址有效，则为true.
     */
    public boolean isValid(String email) {
        if (email == null) {
            return false;
        }

        if (email.endsWith(".")) { // check this first - it's cheap!
            return false;
        }

        // Check the whole email address structure
        Matcher emailMatcher = EMAIL_PATTERN.matcher(email);
        if (!emailMatcher.matches()) {
            return false;
        }

        if (!isValidUser(emailMatcher.group(1))) {
            return false;
        }

        if (!isValidDomain(emailMatcher.group(2))) {
            return false;
        }

        return true;
    }

    /**
     * 如果电子邮件地址的域组件有效，则返回 true.
     *
     * @param domain 正在验证，可能是 IDN 格式
     * @return 如果电子邮件地址的域有效，则为 true.
     */
    protected boolean isValidDomain(String domain) {
        // see if domain is an IP address in brackets
        Matcher ipDomainMatcher = IP_DOMAIN_PATTERN.matcher(domain);

        if (ipDomainMatcher.matches()) {
            InetAddressValidator inetAddressValidator =
                    InetAddressValidator.getInstance();
            return inetAddressValidator.isValid(ipDomainMatcher.group(1));
        }
        // Domain is symbolic name
        if (allowTld) {
            return domainValidator.isValid(domain) || (!domain.startsWith(".") && domainValidator.isValidTld(domain));
        } else {
            return domainValidator.isValid(domain);
        }
    }

    /**
     * 如果电子邮件地址的用户组件有效，则返回 true。
     *
     * @param user 正在验证的用户
     * @return 如果用户名有效，则为 true。
     */
    protected boolean isValidUser(String user) {

        if (user == null || user.length() > MAX_USERNAME_LEN) {
            return false;
        }

        return USER_PATTERN.matcher(user).matches();
    }
}
