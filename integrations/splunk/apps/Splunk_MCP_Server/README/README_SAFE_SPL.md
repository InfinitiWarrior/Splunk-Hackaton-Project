# Safe SPL Configuration

## Overview

The `safe_spl.json` file defines security configurations for SPL (Splunk Processing Language) query execution and tool access control within the MCP (Model Context Protocol) server. This file serves as a security layer to prevent potentially dangerous or unwanted operations from being executed.

## File Structure

The JSON file follows this structure:

```json
{
  "safe_spl_commands": [
    // Array of allowed SPL commands
  ],
  "exclude_tools": [
    // Array of tool names to disable
  ]
}
```

## Configuration Fields

### safe_spl_commands

**Type**: Array of strings  
**Purpose**: Defines the whitelist of SPL commands that are permitted for execution.

This array contains the names of SPL commands that are considered safe to execute. When a user submits an SPL query, the system parses the query and validates that all commands used are present in this whitelist. Any query containing commands not in this list will be rejected.

**Example commands typically included**:
- `search` - Basic search functionality
- `stats` - Statistical calculations
- `eval` - Field evaluation and calculations
- `where` - Filtering results
- `head` - Limiting results from the beginning
- `tail` - Limiting results from the end
- `sort` - Sorting results
- `table` - Formatting output
- `fields` - Field selection
- `rename` - Field renaming
- `dedup` - Removing duplicates
- `timechart` - Time-based charting
- `chart` - General charting
- `top` - Finding top values
- `rare` - Finding rare values
- `lookup` - Lookup operations
- `join` - Joining data
- `append` - Appending results
- `appendcols` - Appending columns
- `union` - Union operations
- `bucket` - Time bucketing
- `convert` - Data conversion
- `fillnull` - Handling null values
- `regex` - Regular expression operations
- `rex` - Field extraction with regex
- `strftime` - Time formatting
- `strptime` - Time parsing
- `multisearch` - Multiple searches
- `subsearch` - Subsearch operations
- `map` - Mapping operations
- `foreach` - Iterative operations
- `eventstats` - Event statistics
- `streamstats` - Streaming statistics
- `transaction` - Transaction grouping
- `cluster` - Event clustering
- `anomalousvalue` - Anomaly detection
- `outlier` - Outlier detection
- `predict` - Predictive analytics
- `trendline` - Trend analysis
- `addinfo` - Adding search info
- `metadata` - Metadata operations
- `dbinspect` - Database inspection
- `rest` - REST API calls (if permitted)
- `inputlookup` - Reading lookup files
- `outputlookup` - Writing lookup files (use with caution)
- `makeresults` - Creating synthetic results
- `gentimes` - Generating time ranges
- `getservice` - Getting service information
- `ai` - AI/ML commands
- `anomalydetection` - Anomaly detection commands

**Security Considerations**: 
- Exclude commands that can modify data (`delete`, `sendemail`, `script`)
- Exclude commands that can access system resources (`collect`, `audit`)
- Exclude commands that can execute arbitrary code (`script`, `run`)
- Carefully consider commands that can write data (`outputlookup`, `collect`)

### exclude_tools

**Type**: Array of strings  
**Purpose**: Defines tools that should be disabled and unavailable for use.

This array contains the names of specific tools that should be excluded from the available tool set, even if they are defined in the `builtin_tools.json` or other tool configuration files. This provides fine-grained control over which tools are accessible.

**Common reasons for excluding tools**:
- **Security concerns**: Tools that provide sensitive system information
- **Administrative functions**: Tools meant for system administration only
- **Resource intensive operations**: Tools that could impact system performance
- **Experimental features**: Tools that are not ready for production use
- **Compliance requirements**: Tools that may violate organizational policies

**Example excluded tools**:
- `get_info` - Exposes system configuration details
- `get_indexes` - Reveals index structure and names
- `get_index_info` - Provides detailed index information
- `get_user_list` - Lists system users
- `get_user_info` - Provides user account details
- `get_metadata` - Exposes system metadata
- `get_kv_store_collections` - Lists KV store collections
- `get_knowledge_objects` - Shows knowledge object configurations
- `generate_spl_from_prompt` - AI-generated SPL (may be unreliable)
- `explain_spl` - SPL explanation features
- `ask_splunk_question` - General question answering
- `optimize_spl` - Query optimization features

## Complete Example

```json
{
  "safe_spl_commands": [
    "search",
    "stats",
    "eval",
    "where",
    "head",
    "tail",
    "sort",
    "table",
    "fields",
    "rename",
    "dedup",
    "timechart",
    "chart",
    "top",
    "rare",
    "lookup",
    "join",
    "append",
    "appendcols",
    "union",
    "bucket",
    "convert",
    "fillnull",
    "regex",
    "rex",
    "strftime",
    "strptime",
    "multisearch",
    "subsearch",
    "map",
    "foreach",
    "eventstats",
    "streamstats",
    "transaction",
    "cluster",
    "anomalousvalue",
    "outlier",
    "predict",
    "trendline",
    "addinfo",
    "metadata",
    "dbinspect",
    "rest",
    "inputlookup",
    "makeresults",
    "gentimes",
    "getservice",
    "ai",
    "anomalydetection"
  ],
  "exclude_tools": [
    "get_info",
    "get_indexes",
    "get_index_info",
    "get_user_list",
    "get_user_info",
    "get_metadata",
    "get_kv_store_collections",
    "get_knowledge_objects",
    "generate_spl_from_prompt",
    "explain_spl",
    "ask_splunk_question",
    "optimize_spl"
  ]
}
```

## Security Model

The safe SPL configuration implements a **whitelist-based security model**:

1. **Default Deny**: Only SPL commands explicitly listed in `safe_spl_commands` are permitted
2. **Query Parsing**: All incoming SPL queries are parsed to extract command names
3. **Command Validation**: Each command is checked against the whitelist
4. **Execution Prevention**: Queries containing non-whitelisted commands are rejected
5. **Tool Filtering**: Tools listed in `exclude_tools` are removed from the available tool set

## Configuration Management

### Empty Configuration
If the `safe_spl.json` file is empty or missing:
- `safe_spl_commands` defaults to an empty set (no commands allowed)
- `exclude_tools` defaults to an empty set (no tools excluded)

### Validation
- SPL commands are validated in lowercase for case-insensitive matching
- Tool exclusion is case-sensitive and must match exact tool names
- Invalid JSON will result in default empty configuration with logging errors

### Performance Impact
- Command validation occurs on every SPL query execution
- Tool filtering happens during tool discovery and listing
- Minimal performance overhead for typical usage patterns

## Best Practices

1. **Principle of Least Privilege**: Only include commands that are necessary for intended use cases
2. **Regular Review**: Periodically review and update the command whitelist
3. **Environment-Specific**: Maintain different configurations for development, staging, and production
4. **Documentation**: Document the reasoning for including or excluding specific commands
5. **Testing**: Thoroughly test configurations before deployment
6. **Monitoring**: Monitor for rejected queries to identify legitimate commands that may need to be added

## Common SPL Commands by Category

### Basic Search and Filtering
- `search`, `where`, `regex`, `rex`

### Data Manipulation
- `eval`, `convert`, `rename`, `fields`, `fillnull`

### Statistical Analysis
- `stats`, `eventstats`, `streamstats`, `chart`, `timechart`

### Data Organization
- `sort`, `head`, `tail`, `dedup`, `table`, `top`, `rare`

### Data Combination
- `join`, `append`, `appendcols`, `union`, `lookup`

### Time Operations
- `bucket`, `strftime`, `strptime`, `gentimes`

### Advanced Analytics
- `predict`, `trendline`, `anomalousvalue`, `outlier`, `cluster`

### Data Generation
- `makeresults`, `map`, `foreach`

## Troubleshooting

### Common Issues

1. **"Forbidden command found"**: Add the required command to `safe_spl_commands`
2. **Tool not available**: Remove the tool name from `exclude_tools`
3. **Query parsing errors**: Check for malformed SPL syntax
4. **Configuration not loading**: Verify JSON syntax and file permissions

### Debugging

Enable debug logging to see:
- Which commands are being validated
- Why specific queries are being rejected
- Tool filtering decisions
- Configuration loading status
