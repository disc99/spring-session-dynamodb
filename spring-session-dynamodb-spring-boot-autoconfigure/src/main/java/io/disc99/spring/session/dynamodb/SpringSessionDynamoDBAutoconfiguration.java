package io.disc99.spring.session.dynamodb;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import io.disc99.spring.session.dynamodb.config.DynamoDBSpringSessionProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.config.annotation.web.http.SpringHttpSessionConfiguration;

@Configuration
public class SpringSessionDynamoDBAutoconfiguration extends SpringHttpSessionConfiguration {

    @Bean
    DynamoDBSpringSessionProperties dynamoDBSpringSessionProperties() {
        return new DynamoDBSpringSessionProperties();
    }

    @Bean
    public DynamoDBSessionRepository createDynamoDBSessionRepository(DynamoDBSpringSessionProperties dynamoDBSpringSessionProperties,
                                                                     DynamoDBMapper dynamoDBMapper) {
        return new DynamoDBSessionRepository(dynamoDBSpringSessionProperties, dynamoDBMapper);
    }
}
