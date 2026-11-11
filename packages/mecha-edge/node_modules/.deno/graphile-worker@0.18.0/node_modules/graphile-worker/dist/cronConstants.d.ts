/** One second in milliseconds */
export declare const SECOND = 1000;
/** One minute in milliseconds */
export declare const MINUTE: number;
/** One hour in milliseconds */
export declare const HOUR: number;
/** One day in milliseconds */
export declare const DAY: number;
/** One week in milliseconds */
export declare const WEEK: number;
/** Separates crontab line into the minute, hour, day of month, month, day of week and command parts. */
export declare const CRONTAB_LINE_PARTS: RegExp;
/** Just the time expression from CRONTAB_LINE_PARTS */
export declare const CRONTAB_TIME_PARTS: RegExp;
/** Matches an explicit numeric value */
export declare const CRONTAB_NUMBER: RegExp;
/** Matches a range of numeric values */
export declare const CRONTAB_RANGE: RegExp;
/** Matches a numeric wildcard, optionally with a divisor */
export declare const CRONTAB_WILDCARD: RegExp;
/** Splits the command from the crontab line into the task, options and payload. */
export declare const CRONTAB_COMMAND: RegExp;
/** Matches the id=UID option, capturing the unique identifier */
export declare const CRONTAB_OPTIONS_ID: RegExp;
/** Matches the fill=t option, capturing the time phrase  */
export declare const CRONTAB_OPTIONS_BACKFILL: RegExp;
/** Matches the max=n option, capturing the max executions number */
export declare const CRONTAB_OPTIONS_MAX: RegExp;
/** Matches the queue=name option, capturing the queue name */
export declare const CRONTAB_OPTIONS_QUEUE: RegExp;
/** Matches the jobKey=foo option, capturing the unique identifier for the job */
export declare const CRONTAB_OPTIONS_JOB_KEY: RegExp;
/** Matches the jobKeyMode=replace option, defining the replacement strategy this job */
export declare const CRONTAB_OPTIONS_JOB_KEY_MODE: RegExp;
/** Matches the priority=n option, capturing the priority value */
export declare const CRONTAB_OPTIONS_PRIORITY: RegExp;
/** Matches the quantity and period string at the beginning of a timephrase */
export declare const TIMEPHRASE_PART: RegExp;
export declare const PERIOD_DURATIONS: {
    s: number;
    m: number;
    h: number;
    d: number;
    w: number;
};
