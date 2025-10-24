# Contributing to Threat Intelligence

Thank you for your interest in contributing to Threat Intelligence! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Security](#security)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.70+ (latest stable recommended)
- Git
- Understanding of threat intelligence and security
- Familiarity with HTTP APIs and data parsing
- Basic knowledge of threat intelligence sources (MITRE ATT&CK, CVE, etc.)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/threat-intel.git
   cd threat-intel
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/redasgard/threat-intel.git
   ```

## How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Check the documentation** in the `docs/` folder
3. **Verify the issue** with the latest version
4. **Test with minimal examples**

When creating an issue, include:

- **Clear description** of the problem
- **Steps to reproduce** with code examples
- **Expected vs actual behavior**
- **Environment details** (OS, Rust version, network conditions)
- **Source-specific details** (if related to specific threat intel sources)

### Suggesting Enhancements

For feature requests:

1. **Check existing issues** and roadmap
2. **Describe the use case** clearly
3. **Explain the security benefit**
4. **Consider implementation complexity**
5. **Provide source examples** if applicable

### Pull Requests

#### Before You Start

1. **Open an issue first** for significant changes
2. **Discuss the approach** with maintainers
3. **Ensure the change aligns** with project goals
4. **Consider network and performance implications**

#### PR Process

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our guidelines

3. **Test thoroughly**:
   ```bash
   cargo test
   cargo test --features tracing
   cargo clippy
   cargo fmt
   ```

4. **Update documentation** if needed

5. **Commit with clear messages**:
   ```bash
   git commit -m "Add support for new threat intelligence source"
   ```

6. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

#### PR Requirements

- **All tests pass** (CI will check)
- **Code is formatted** (`cargo fmt`)
- **No clippy warnings** (`cargo clippy`)
- **Documentation updated** if needed
- **Clear commit messages**
- **PR description** explains the change
- **Network tests** pass (if applicable)

## Development Setup

### Project Structure

```
threat-intel/
├── src/                 # Source code
│   ├── lib.rs          # Main library interface
│   ├── sources/        # Threat intelligence sources
│   ├── feeds/          # Feed fetching and parsing
│   ├── parsers/        # Data format parsers
│   ├── assessment.rs   # Risk assessment logic
│   └── config.rs       # Configuration management
├── tests/              # Integration tests
├── examples/           # Usage examples
└── docs/               # Documentation
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with tracing
cargo test --features tracing

# Run specific test
cargo test test_mitre_attack_source

# Run network tests (requires internet)
cargo test -- --ignored

# Run examples
cargo run --example basic_usage
```

### Code Style

We follow standard Rust conventions:

- **Format code**: `cargo fmt`
- **Check linting**: `cargo clippy`
- **Use meaningful names**
- **Add documentation** for public APIs
- **Write tests** for new functionality
- **Consider async performance**

## Testing

### Test Categories

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test complete workflows
3. **Network Tests**: Test with real threat intel sources
4. **Mock Tests**: Test with mocked data
5. **Performance Tests**: Test async operations

### Adding Tests

When adding new functionality:

1. **Write unit tests** for each function
2. **Add integration tests** for workflows
3. **Test with real sources** (if applicable)
4. **Test error handling** and edge cases
5. **Test async operations**

Example test structure:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_source_integration() {
        let config = ThreatIntelConfig::default();
        let mut engine = ThreatIntelEngine::new(config);
        
        // Test source initialization
        let result = engine.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_new_source_network() {
        let config = ThreatIntelConfig::default();
        let mut engine = ThreatIntelEngine::new(config);
        
        // Test network operations
        let result = engine.sync().await;
        assert!(result.is_ok());
    }
}
```

## Security

### Security Considerations

Threat Intelligence is a security-critical library. When contributing:

1. **Understand threat intelligence** before making changes
2. **Test with real threat data** (safely)
3. **Consider data sensitivity** and privacy
4. **Review security implications** of changes
5. **Test with various sources**

### Security Testing

```bash
# Run source tests
cargo test test_mitre_attack_source
cargo test test_cve_database_source
cargo test test_abuse_ch_source

# Test with examples
cargo run --example basic_usage
```

### Threat Intelligence Sources

When adding new sources:

1. **Research the source** and its API
2. **Understand the data format**
3. **Test with real data** (safely)
4. **Consider rate limiting** and authentication
5. **Document the source** and its capabilities

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead:
1. Email security@redasgard.com
2. Include detailed description
3. Include source examples
4. Wait for response before disclosure

## Documentation

### Documentation Standards

- **Public APIs** must have doc comments
- **Examples** in doc comments should be runnable
- **Security implications** should be documented
- **Performance characteristics** should be noted
- **Source capabilities** should be documented

### Documentation Structure

```
docs/
├── README.md              # Main documentation
├── getting-started.md      # Quick start guide
├── api-reference.md       # Complete API docs
├── sources.md            # Source documentation
├── best-practices.md      # Usage guidelines
└── faq.md                 # Frequently asked questions
```

### Writing Documentation

1. **Use clear, concise language**
2. **Include practical examples**
3. **Explain security implications**
4. **Document source capabilities**
5. **Link to related resources**
6. **Keep it up to date**

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

Before releasing:

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in Cargo.toml
- [ ] Security review completed
- [ ] Performance benchmarks updated
- [ ] Source tests updated

### Release Steps

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md**
3. **Create release PR**
4. **Review and merge**
5. **Tag release** on GitHub
6. **Publish to crates.io**

## Areas for Contribution

### High Priority

- **New threat intelligence sources**: Add support for additional sources
- **Data format parsers**: Support for XML, STIX, TAXII formats
- **Performance improvements**: Optimize async operations and caching
- **Risk assessment**: Improve risk scoring algorithms

### Medium Priority

- **Configuration options**: More flexible source configuration
- **Caching improvements**: Better caching strategies
- **Error handling**: Better error messages and recovery
- **Testing**: More comprehensive test coverage

### Low Priority

- **CLI tools**: Command-line utilities for threat intel
- **Webhook support**: Real-time threat intelligence updates
- **Database backends**: Persistent storage options
- **Visualization**: Threat intelligence visualization tools

## Threat Intelligence Source Development

### Source Categories

1. **Vulnerability Sources**: CVE databases, security advisories
2. **Threat Actor Sources**: MITRE ATT&CK, threat actor databases
3. **IOC Sources**: Abuse.ch, malware databases
4. **Custom Sources**: Internal threat feeds, proprietary sources

### Source Development Process

1. **Research**: Understand the source and its API
2. **Analyze**: Understand the data format and structure
3. **Implement**: Create source integration
4. **Test**: Test with real data (safely)
5. **Validate**: Ensure data quality and accuracy
6. **Document**: Document the source and its capabilities

### Source Testing

```rust
// Test new source
#[tokio::test]
async fn test_new_source() {
    let config = ThreatIntelConfig::default();
    let mut engine = ThreatIntelEngine::new(config);
    
    // Test source initialization
    let result = engine.initialize().await;
    assert!(result.is_ok());
    
    // Test data fetching
    let data = engine.query_vulnerabilities("test", "1.0").await;
    assert!(data.is_ok());
}
```

## Getting Help

### Resources

- **Documentation**: Check the `docs/` folder
- **Examples**: Look at `examples/` folder
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions

### Contact

- **Email**: hello@redasgard.com
- **GitHub**: [@redasgard](https://github.com/redasgard)
- **Security**: security@redasgard.com

## Recognition

Contributors will be:

- **Listed in CONTRIBUTORS.md**
- **Mentioned in release notes** for significant contributions
- **Credited in documentation** for major features
- **Acknowledged** for source research

Thank you for contributing to Threat Intelligence! 🎯🛡️
