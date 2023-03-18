package io.disc99.spring.session.dynamodb;

import com.amazonaws.services.dynamodbv2.datamodeling.*;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.TableNameOverride;
import io.disc99.spring.session.dynamodb.config.DynamoDBSpringSessionProperties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.session.Session;
import org.springframework.util.SerializationUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Slf4j
public class DynamoDBSessionRepository implements
        FindByIndexNameSessionRepository<DynamoDBSessionRepository.DynamoDBSession> {

    private static final String KEY_NAMESPACE = ":spring:session:sessions:";

    DynamoDBSpringSessionProperties properties;
    DynamoDBRepository repository;

    public DynamoDBSessionRepository(DynamoDBSpringSessionProperties properties, DynamoDBMapper dynamoDBMapper) {
        DynamoDBMapperConfig config = new DynamoDBMapperConfig.Builder()
                .withTableNameOverride(TableNameOverride.withTableNameReplacement(properties.getTableName()))
                .build();
        this.properties = properties;
        this.repository = new DynamoDBRepository(dynamoDBMapper, config);
    }

    @Override
    public Map<String, DynamoDBSession> findByIndexNameAndIndexValue(String indexName, String indexValue) {
        if (!PRINCIPAL_NAME_INDEX_NAME.equals(indexName)) {
            return Collections.emptyMap();
        }
        return null;
    }

    @Override
    public DynamoDBSession createSession() {
        MapSession cached = new MapSession();
        cached.setMaxInactiveInterval(Duration.ofSeconds(properties.getMaxInactiveIntervalInSeconds()));
        return new DynamoDBSession(cached, true);
    }

    @Override
    public void save(DynamoDBSession session) {
        if (!session.isNew) {
            String key = getSessionKey(session.hasChangedSessionId() ? session.originalSessionId : session.getId());
            repository.findById(key)
                    .orElseThrow(() -> new IllegalStateException("Session was invalidated"));
        }
        session.save();
    }


    private String getSessionKey(String sessionId) {
        return properties.getKeyNamespacePrefix() + KEY_NAMESPACE + sessionId;
    }

    @Override
    public DynamoDBSession findById(String id) {
        String key = getSessionKey(id);
        Optional<Map<String, Object>> sessionItem = repository.findById(key);
        if (!sessionItem.isPresent()) {
            return null;
        }
        Map<String, Object> map = sessionItem.get();

        MapSession session = new MapSession(id);
        Long creationTime = (Long) map.get(CREATION_TIME_KEY);
        if (creationTime == null) {
            handleMissingKey(CREATION_TIME_KEY);
        }
        session.setCreationTime(Instant.ofEpochMilli(creationTime));
        Long lastAccessedTime = (Long) map.get(LAST_ACCESSED_TIME_KEY);
        if (lastAccessedTime == null) {
            handleMissingKey(LAST_ACCESSED_TIME_KEY);
        }
        session.setLastAccessedTime(Instant.ofEpochMilli(lastAccessedTime));
        Integer maxInactiveInterval = (Integer) map.get(MAX_INACTIVE_INTERVAL_KEY);
        if (maxInactiveInterval == null) {
            handleMissingKey(MAX_INACTIVE_INTERVAL_KEY);
        }
        session.setMaxInactiveInterval(Duration.ofSeconds(maxInactiveInterval));
        map.forEach((name, value) -> {
            if (name.startsWith(ATTRIBUTE_PREFIX)) {
                session.setAttribute(name.substring(ATTRIBUTE_PREFIX.length()), value);
            }
        });
        if (session.isExpired()) {
            deleteById(id);
            return null;
        }

        return new DynamoDBSession(session, false);
    }

    private static void handleMissingKey(String key) {
        throw new IllegalStateException(key + " key must not be null");
    }

    @Override
    public void deleteById(String id) {
        String key = getSessionKey(id);
        repository.delete(key);
    }

    static final String CREATION_TIME_KEY = "creationTime";
    static final String LAST_ACCESSED_TIME_KEY = "lastAccessedTime";
    static final String MAX_INACTIVE_INTERVAL_KEY = "maxInactiveInterval";
    static final String ATTRIBUTE_PREFIX = "sessionAttr:";

    /**
     * @see org.springframework.session.data.redis.RedisSessionRepository.RedisSession
     */
    @SuppressWarnings("JavadocReference")
    class DynamoDBSession implements Session {
        private final MapSession cached;
        private final Map<String, Object> delta = new HashMap<>();
        private boolean isNew;
        private String originalSessionId;

        DynamoDBSession(MapSession cached, boolean isNew) {
            this.cached = cached;
            this.isNew = isNew;
            this.originalSessionId = cached.getId();
            if (this.isNew) {
                this.delta.put(DynamoDBSessionRepository.CREATION_TIME_KEY, cached.getCreationTime().toEpochMilli());
                this.delta.put(DynamoDBSessionRepository.MAX_INACTIVE_INTERVAL_KEY, (int) cached.getMaxInactiveInterval().getSeconds());
                this.delta.put(DynamoDBSessionRepository.LAST_ACCESSED_TIME_KEY, cached.getLastAccessedTime().toEpochMilli());
                getAttributeNames().forEach((attributeName) -> this.delta.put(getAttributeKey(attributeName), cached.getAttribute(attributeName)));
            }
        }

        @Override
        public String getId() {
            return this.cached.getId();
        }

        @Override
        public String changeSessionId() {
            return this.cached.changeSessionId();
        }

        @Override
        public <T> T getAttribute(String attributeName) {
            T attributeValue = this.cached.getAttribute(attributeName);
            if (attributeValue != null) {
                this.delta.put(getAttributeKey(attributeName), attributeValue);
            }
            return attributeValue;
        }

        @Override
        public Set<String> getAttributeNames() {
            return this.cached.getAttributeNames();
        }

        @Override
        public void setAttribute(String attributeName, Object attributeValue) {
            this.cached.setAttribute(attributeName, attributeValue);
            this.delta.put(getAttributeKey(attributeName), attributeValue);
        }

        @Override
        public void removeAttribute(String attributeName) {
            setAttribute(attributeName, null);
        }

        @Override
        public Instant getCreationTime() {
            return this.cached.getCreationTime();
        }

        @Override
        public void setLastAccessedTime(Instant lastAccessedTime) {
            this.cached.setLastAccessedTime(lastAccessedTime);
            this.delta.put(DynamoDBSessionRepository.LAST_ACCESSED_TIME_KEY, getLastAccessedTime().toEpochMilli());
        }

        @Override
        public Instant getLastAccessedTime() {
            return this.cached.getLastAccessedTime();
        }

        @Override
        public void setMaxInactiveInterval(Duration interval) {
            this.cached.setMaxInactiveInterval(interval);
            this.delta.put(DynamoDBSessionRepository.MAX_INACTIVE_INTERVAL_KEY, (int) getMaxInactiveInterval().getSeconds());
        }

        @Override
        public Duration getMaxInactiveInterval() {
            return this.cached.getMaxInactiveInterval();
        }

        @Override
        public boolean isExpired() {
            return this.cached.isExpired();
        }


        private boolean hasChangedSessionId() {
            return !getId().equals(this.originalSessionId);
        }

        private void save() {
            saveChangeSessionId();
            saveDelta();
            if (this.isNew) {
                this.isNew = false;
            }
        }

        private void saveChangeSessionId() {
            if (hasChangedSessionId()) {
                if (!this.isNew) {
                    String originalSessionIdKey = getSessionKey(this.originalSessionId);
                    String sessionIdKey = getSessionKey(getId());
                    repository.updateId(originalSessionIdKey, sessionIdKey);
                }
                this.originalSessionId = getId();
            }
        }

        private void saveDelta() {
            if (this.delta.isEmpty()) {
                return;
            }
            String key = getSessionKey(getId());
//            config.cacheTtl() == 0 ? 0 : Instant.now().getEpochSecond() + config.cacheTtl()
            Instant instant = Instant.ofEpochMilli(getLastAccessedTime().toEpochMilli())
                    .plusSeconds(getMaxInactiveInterval().getSeconds());
            repository.save(key, delta, instant.getEpochSecond());
            this.delta.clear();
        }

    }

    private static String getAttributeKey(String attributeName) {
        return ATTRIBUTE_PREFIX + attributeName;
    }

    @SuppressWarnings("unused")
    @DynamoDBTable(tableName = DynamoDBSpringSessionProperties.DEFAULT_SESSIONS_TABLE_NAME)
    public static class SessionItem {
        String pk;
        String sk;
        String data;
        long expirationTime;

        @DynamoDBHashKey(attributeName = "PK")
        public String getPk() {
            return pk;
        }

        public void setPk(String pk) {
            this.pk = pk;
        }

        @DynamoDBRangeKey(attributeName = "SK")
        public String getSk() {
            return sk;
        }

        public void setSk(String sk) {
            this.sk = sk;
        }

        @DynamoDBAttribute(attributeName = "Data")
        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }

        @DynamoDBAttribute(attributeName = "ExpirationTime")
        public long getExpirationTime() {
            return expirationTime;
        }

        public void setExpirationTime(long expirationTime) {
            this.expirationTime = expirationTime;
        }
    }

    @AllArgsConstructor
    static class DynamoDBRepository {
        private static final Base64.Encoder ENCODER = Base64.getEncoder();
        private static final Base64.Decoder DECODER = Base64.getDecoder();

        DynamoDBMapper dynamoDBMapper;
        DynamoDBMapperConfig config;

        void save(String id, Map<String, Object> data, long ttl) {
            Map<String, Object> inputData = findById(id)
                    .map(map -> {
                        map.putAll(data);
                        return map;
                    }).orElse(data);

            SessionItem sessionItem = new SessionItem();
            sessionItem.setPk(id);
            sessionItem.setSk(id);
            byte[] bytes = Objects.requireNonNull(SerializationUtils.serialize(inputData));
            sessionItem.setData(ENCODER.encodeToString(bytes));
            sessionItem.setExpirationTime(ttl);
            dynamoDBMapper.save(sessionItem, config);
        }

        @SuppressWarnings("unchecked")
        Optional<Map<String, Object>> findById(String id) {
            SessionItem sessionItem = dynamoDBMapper.load(SessionItem.class, id, id, config);
            if (sessionItem == null) {
                return Optional.empty();
            }
            byte[] decodedMap = DECODER.decode(sessionItem.getData());
            Map<String, Object> map = (Map<String, Object>) deserialize(decodedMap);
            return Optional.of(map);
        }

        public static Object deserialize(@Nullable byte[] bytes) {
            if (bytes == null) {
                return null;
            }
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                return ois.readObject();
            } catch (IOException ex) {
                throw new IllegalArgumentException("Failed to deserialize object", ex);
            } catch (ClassNotFoundException ex) {
                throw new IllegalStateException("Failed to deserialize object type", ex);
            }
        }


        public void delete(String id) {
            SessionItem sessionItem = new SessionItem();
            sessionItem.setPk(id);
            sessionItem.setSk(id);
            dynamoDBMapper.delete(sessionItem, config);
        }

        public void updateId(String oldId, String newId) {
            // TODO item if null case (expired)
            SessionItem item = dynamoDBMapper.load(SessionItem.class, oldId, oldId, config);
            item.setPk(newId);
            item.setSk(newId);
            dynamoDBMapper.save(item, config);
            dynamoDBMapper.delete(oldId, config);
        }
    }
}
