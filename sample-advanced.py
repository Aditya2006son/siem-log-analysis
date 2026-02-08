import json

parsed_log = parse_failed_login(log_line)

if parsed_log:
    print(json.dumps(parsed_log, indent=4))


//Added log parsing and normalization module for SSH authentication logs

//- Implemented regex-based parsing for failed login attempts
//- Structured parsed logs into JSON format
//- Prepared data for future detection rule integration
