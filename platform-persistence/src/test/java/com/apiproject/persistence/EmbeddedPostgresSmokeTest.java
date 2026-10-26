package com.apiproject.persistence;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EmbeddedPostgresSmokeTest {

    @Test
    void startsRealPostgresAndExecutesSql() throws Exception {
        try (EmbeddedPostgres postgres = EmbeddedPostgres.builder().start()) {
            DataSource dataSource = postgres.getPostgresDatabase();
            try (Connection connection = dataSource.getConnection();
                 Statement statement = connection.createStatement()) {
                assertEquals(18, connection.getMetaData().getDatabaseMajorVersion());
                statement.execute("""
                        CREATE TABLE smoke_test (
                            id UUID PRIMARY KEY,
                            payload JSONB NOT NULL
                        )
                        """);
                statement.execute("""
                        INSERT INTO smoke_test (id, payload)
                        VALUES ('00000000-0000-0000-0000-000000000001', '{"ok":true}')
                        """);
                try (var resultSet = statement.executeQuery(
                        "SELECT payload ->> 'ok' FROM smoke_test")) {
                    resultSet.next();
                    assertEquals("true", resultSet.getString(1));
                }
            }
        }
    }
}
