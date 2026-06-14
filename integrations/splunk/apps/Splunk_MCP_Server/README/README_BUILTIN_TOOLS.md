# Builtin Tools Configuration

## Overview

The `builtin_tools.json` file defines a collection of pre-configured tools that are available for use with the MCP (Model Context Protocol) server. This file contains tool definitions that specify how to interact with Splunk through structured queries and parameters.

## File Structure

The JSON file follows this top-level structure:

```json
{
  "tools": [
    {
      // Tool definition objects
    }
  ]
}
```

## Tool Definition Format

Each tool in the `tools` array is a JSON object with the following properties:

### Required Fields

- **`name`** (string): Unique identifier for the tool. Must be unique across all tools.
- **`spl`** (string): The Splunk Processing Language (SPL) query template that will be executed when the tool is called.

### Optional Core Fields

- **`description`** (string): Human-readable description of what the tool does and when to use it.
- **`category`** (string): Logical grouping category for organizing tools (e.g., "security", "performance", "data-analysis").
- **`version`** (string): Version identifier for the tool definition.
- **`tags`** (array of strings): Descriptive tags for categorization and searchability.
- **`scalar`** (boolean): Indicates if the tool returns scalar values. Affects how arguments are injected. Defaults to `false`.
- **`time_range`** (boolean): Whether the tool supports time range parameters. Defaults to `true`.
- **`required_app`** (string): Name of the Splunk app that must be installed for this tool to function.

### Arguments Array

The **`arguments`** field is an array of argument definition objects. Each argument object can contain:

#### Required Argument Fields
- **`name`** (string): The parameter name used in the SPL template.

#### Optional Argument Fields
- **`type`** (string): Data type of the argument. Valid values:
  - `"string"` (default)
  - `"integer"`
  - `"number"`
  - `"boolean"`
- **`description`** (string): Human-readable description of the argument's purpose.
- **`required`** (boolean): Whether the argument must be provided. Defaults to `false`.
- **`placeholder`** (string): Example value shown in UI as a hint.
- **`default`** (any): Default value used when argument is not provided.
- **`group`** (string): Logical grouping for UI organization.
- **`display_order`** (integer): Suggested ordering for UI display.
- **`quoted`** (boolean): Whether string values should be quoted in the SPL query. Defaults to `true`.

#### Numeric Constraints (for `integer` and `number` types)
- **`min`** (number): Minimum allowed value.
- **`max`** (number): Maximum allowed value.

#### Value Constraints
- **`enum`** (array or object): List of allowed values or key-value pairs for dropdown selections.

#### Validation Rules
- **`validation`** (object): Custom validation configuration:
  - **`pattern`** (string): Regular expression pattern for value validation.
  - **`message`** (string): Custom error message for validation failures.

### Examples Array

The **`examples`** field is an array of usage example objects. Each example can contain:

- **`name`** (string): Title or name of the example.
- **`description`** (string): Description of what the example demonstrates.
- **`arguments`** (object): Key-value pairs showing example argument values.
- **`expected_use`** (string): Description of the expected use case or outcome.

## Standard Arguments

Tools automatically receive standard arguments unless they are defined as `scalar: true`:

- **`earliest_time`**: Start time for search (default: "-24h")
- **`latest_time`**: End time for search (default: "now")  
- **`row_limit`**: Maximum number of rows to return (default: configured system limit)

## SPL Template Variables

In the `spl` field, argument values are injected using template variable syntax. The exact substitution mechanism depends on the tool implementation.

## Complete Example

```json
{
  "tools": [
    {
      "name": "search_events",
      "description": "Search for events in Splunk indexes with flexible filtering",
      "category": "search",
      "version": "1.0.0",
      "tags": ["search", "events", "general"],
      "time_range": true,
      "spl": "search index={index} {search_terms} | head {row_limit}",
      "arguments": [
        {
          "name": "index",
          "type": "string",
          "description": "Splunk index to search",
          "required": true,
          "placeholder": "main",
          "group": "search_params"
        },
        {
          "name": "search_terms",
          "type": "string", 
          "description": "Search terms and filters",
          "required": false,
          "placeholder": "error OR warning",
          "default": "*",
          "group": "search_params"
        },
        {
          "name": "severity_level",
          "type": "string",
          "description": "Filter by severity level",
          "required": false,
          "enum": ["low", "medium", "high", "critical"],
          "group": "filters"
        }
      ],
      "examples": [
        {
          "name": "Basic Error Search",
          "description": "Search for error events in the main index",
          "arguments": {
            "index": "main",
            "search_terms": "error",
            "earliest_time": "-1h"
          },
          "expected_use": "Find recent error events for troubleshooting"
        }
      ]
    },
    {
      "name": "get_host_count",
      "description": "Count unique hosts in an index",
      "category": "analytics",
      "scalar": true,
      "time_range": false,
      "spl": "| metadata type=hosts index={index} | stats count",
      "arguments": [
        {
          "name": "index",
          "type": "string",
          "description": "Index to analyze",
          "required": true,
          "validation": {
            "pattern": "^[a-zA-Z0-9_-]+$",
            "message": "Index name must contain only alphanumeric characters, underscores, and hyphens"
          }
        }
      ]
    }
  ]
}
```

## Important Considerations

1. **Tool Names**: Must be unique across all tools and should follow a consistent naming convention.

2. **SPL Security**: The SPL queries should be designed with security in mind, avoiding potential injection vulnerabilities.

3. **Argument Validation**: Use validation patterns and constraints to ensure data integrity and security.

4. **Performance**: Consider the performance impact of SPL queries, especially for frequently used tools.

5. **Dependencies**: Use the `required_app` field to specify when tools depend on specific Splunk applications.

6. **Quoted vs Unquoted Arguments**: Set `quoted: false` for arguments that should not be quoted in SPL (like time values, numbers, or field names).

7. **Enum Constraints**: Avoid using `enum` with `quoted: true` arguments as this creates a logical conflict between free-form text input and predefined values.

## Validation

The builtin_tools.json file should be validated against the corresponding JSON schema to ensure proper structure and prevent runtime errors. All tools defined in this file are automatically loaded and made available through the MCP server interface.
