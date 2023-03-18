package io.disc99.spring.session.dynamodb.config;

import lombok.Data;

@Data
public class DynamoDBSpringSessionProperties {
    public static final int MAX_INACTIVE_INTERVAL_IN_SECONDS = 20 * 60;
    public static final String DEFAULT_SESSIONS_TABLE_NAME = "Sessions";

    String keyNamespacePrefix;
    String tableName = DEFAULT_SESSIONS_TABLE_NAME;
    Integer maxInactiveIntervalInSeconds = MAX_INACTIVE_INTERVAL_IN_SECONDS;
}
