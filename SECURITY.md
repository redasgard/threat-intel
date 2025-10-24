# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security bugs seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@redasgard.com**

### What to Include

When reporting a security vulnerability, please include:

1. **Description**: A clear description of the vulnerability
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Impact**: Description of the potential impact
4. **Environment**: OS, Rust version, network configuration, and any other relevant details
5. **Proof of Concept**: If possible, include a minimal code example that demonstrates the issue

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Regular Updates**: We will keep you informed of our progress
- **Resolution**: We will work with you to resolve the issue and coordinate disclosure

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution**: Within 30 days (depending on complexity)

## Security Considerations

### Threat Intelligence Specific Concerns

When reporting vulnerabilities, please consider:

1. **Data Exposure**: Unauthorized access to threat intelligence data
2. **Authentication Bypass**: Bypass of API authentication mechanisms
3. **Data Injection**: Malicious data injection into threat feeds
4. **Network Security**: Insecure network communications
5. **Performance**: DoS through resource exhaustion
6. **Memory Safety**: Unsafe memory operations or buffer overflows

### Attack Vectors

Common attack vectors to test:

- **API Key Exposure**: Leaked or weak API keys
- **Authentication Bypass**: Bypass of auth mechanisms
- **Data Injection**: Malicious data in threat feeds
- **Network Attacks**: Man-in-the-middle, DNS spoofing
- **Cache Poisoning**: Malicious data in cache
- **Rate Limiting**: Bypass of rate limiting mechanisms
- **Input Validation**: Malicious input to threat sources

## Security Best Practices

### For Users

1. **Secure API Keys**: Store API keys securely
2. **Use HTTPS**: Always use secure connections
3. **Validate Data**: Validate threat intelligence data
4. **Keep the library updated** to the latest version
5. **Monitor for security advisories**
6. **Implement proper access controls**

### For Developers

1. **Test with malicious inputs** regularly
2. **Implement defense in depth**
3. **Use the library correctly** according to documentation
4. **Consider additional validation** for critical applications
5. **Monitor security updates**
6. **Implement proper logging and monitoring**

## Security Features

### Built-in Protections

- **Secure HTTP**: HTTPS-only connections
- **Authentication**: Multiple auth methods supported
- **Data Validation**: Input validation and sanitization
- **Error Handling**: Secure error handling
- **Memory Safety**: Rust's memory safety guarantees
- **Configurable Security**: Adjustable security settings

### Additional Recommendations

- **API Key Management**: Secure storage and rotation
- **Network Security**: Use secure network configurations
- **Data Validation**: Validate all threat intelligence data
- **Access Controls**: Implement proper access controls
- **Logging**: Log security events for monitoring
- **Regular Updates**: Keep dependencies and the library updated

## Security Updates

### How We Handle Security Issues

1. **Assessment**: We assess the severity and impact
2. **Fix Development**: We develop a fix in private
3. **Testing**: We thoroughly test the fix
4. **Release**: We release the fix with a security advisory
5. **Disclosure**: We coordinate disclosure with reporters

### Security Advisories

Security advisories are published on:

- **GitHub Security Advisories**: https://github.com/redasgard/threat-intel/security/advisories
- **Crates.io**: Security notices in release notes
- **Email**: Subscribers to security@redasgard.com

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Report vulnerabilities privately first
2. **Coordinated Disclosure**: We coordinate disclosure timing
3. **Credit**: We give credit to security researchers
4. **No Legal Action**: We won't take legal action against good faith research

## Security Research

### Guidelines for Security Researchers

- **Test Responsibly**: Don't test on production systems
- **Respect Privacy**: Don't access or modify data
- **Report Promptly**: Report findings as soon as possible
- **Follow Guidelines**: Follow this security policy

### Scope

**In Scope:**
- Data exposure vulnerabilities
- Authentication bypasses
- Data injection attacks
- Network security issues
- Memory safety issues
- Performance DoS attacks

**Out of Scope:**
- Social engineering attacks
- Physical security issues
- Issues in dependencies (report to their maintainers)
- Issues in applications using this library
- Issues in threat intelligence sources themselves

## Contact

For security-related questions or to report vulnerabilities:

- **Email**: security@redasgard.com
- **PGP Key**: Available upon request
- **Response Time**: Within 48 hours

## Acknowledgments

We thank the security researchers who help keep our software secure. Security researchers who follow responsible disclosure practices will be acknowledged in our security advisories.

## Legal

By reporting a security vulnerability, you agree to:

1. **Not disclose** the vulnerability publicly until we've had a chance to address it
2. **Not access or modify** data that doesn't belong to you
3. **Not disrupt** our services or systems
4. **Act in good faith** to avoid privacy violations, destruction of data, and interruption or degradation of our services

Thank you for helping keep Threat Intelligence and our users safe! 🎯🛡️
